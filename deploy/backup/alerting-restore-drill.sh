#!/usr/bin/env bash
# Restore drill. Run quarterly; see docs/09-deployment.md §7.
#
# The pass criterion is the point. "The restore completed" proves nothing about an
# audit chain. What proves something is verifying the restored chain against heads the
# AUDITORS hold — not heads that came out of the same backup, which a tampered backup
# would carry happily.
#
# The drill restores into a scratch database and drops it afterwards. It never
# touches the live one: a restore drill that can overwrite production is a disaster
# waiting for a tired operator and a missing argument.
#
#   ./alerting-restore-drill.sh <backup-dir> [auditor-heads.json]
set -Eeuo pipefail

backup="${1:?usage: alerting-restore-drill.sh <backup-dir> [auditor-heads.json]}"
auditor_heads="${2:-}"
: "${ALERTING_PYTHON:=/opt/alerting/current/venv/bin/python}"
: "${ALERTING_AUDITOR:=/opt/alerting/current/venv/bin/alerting-auditor}"
: "${ALERTING_PG_BIN:=/usr/lib/postgresql/16/bin}"
# Where the scratch database is created. Points at the maintenance database, so the
# drill can `CREATE DATABASE` without connecting to the live one.
: "${ALERTING_MAINTENANCE_DSN:?ALERTING_MAINTENANCE_DSN is not set (owner role, e.g. .../postgres)}"

scratch="alerting_restore_drill_$(date -u +%Y%m%d%H%M%S)"
workdir="$(mktemp -d)"

log()  { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "DRILL FAILED: $*"; exit 1; }

cleanup() {
    rm -rf "$workdir"
    "${ALERTING_PG_BIN}/psql" -q -d "$ALERTING_MAINTENANCE_DSN" \
        -c "DROP DATABASE IF EXISTS ${scratch}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v "$ALERTING_AUDITOR" >/dev/null 2>&1 || fail "auditor CLI not found: ${ALERTING_AUDITOR}"
[ -x "${ALERTING_PG_BIN}/pg_restore" ] || fail "pg_restore not found in ${ALERTING_PG_BIN}"
[ -f "${backup}/alerting.dump" ] || fail "no alerting.dump in ${backup}"

log "restoring into scratch database ${scratch}"
"${ALERTING_PG_BIN}/psql" -q -v ON_ERROR_STOP=1 -d "$ALERTING_MAINTENANCE_DSN" \
    -c "CREATE DATABASE ${scratch}" || fail "could not create the scratch database — the owner role needs CREATEDB (see deploy/postgres/roles.sql)"

# The scratch DSN is the maintenance one with the database name swapped.
scratch_dsn="${ALERTING_MAINTENANCE_DSN%/*}/${scratch}"

"${ALERTING_PG_BIN}/pg_restore" --exit-on-error --no-owner --dbname="$scratch_dsn" \
    "${backup}/alerting.dump" || fail "pg_restore"

log "checking that the restored copy is still append-only"
"${ALERTING_PG_BIN}/psql" -q -t -A -v ON_ERROR_STOP=1 -d "$scratch_dsn" <<'SQL' \
    | grep -qx 'ok' || fail "append-only guards did not survive the restore"
SELECT CASE WHEN count(*) = 3 THEN 'ok' ELSE 'missing:' || count(*) END
FROM pg_trigger
WHERE tgrelid = 'audit_log'::regclass
  AND NOT tgisinternal
  AND tgname IN ('audit_log_no_update', 'audit_log_no_delete', 'audit_log_no_truncate');
SQL
log "integrity and append-only guards: ok"

log "verifying the chain inside the restored copy"
"$ALERTING_AUDITOR" verify --dsn "$scratch_dsn" || fail "chain does not verify"

if [ -n "$auditor_heads" ]; then
    log "verifying against auditor-held heads: ${auditor_heads}"
    "$ALERTING_AUDITOR" pull --dsn "$scratch_dsn" --out "${workdir}/chain.json"
    "$ALERTING_PYTHON" - "${workdir}/chain.json" "$auditor_heads" <<'PY' \
        || fail "restored chain does not reach the auditors' heads"
import json
import sys

chain = json.load(open(sys.argv[1]))
held = json.load(open(sys.argv[2]))
mismatched = [idx for idx, head in held.items() if chain["heads"].get(str(idx)) != head]
if mismatched:
    raise SystemExit(f"heads disagree at: {mismatched}")
print(f"all {len(held)} auditor-held head(s) matched")
PY
else
    log "NOTE: no auditor heads supplied. The chain verified internally, which does"
    log "      NOT detect a rewritten tail — that is what published heads are for."
    log "      Supply them to make this drill meaningful."
fi

log "restore drill passed"
