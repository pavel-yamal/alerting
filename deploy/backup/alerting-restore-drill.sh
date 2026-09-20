#!/usr/bin/env bash
# Restore drill. Run quarterly; see docs/09-deployment.md §7.
#
# The pass criterion is the point. "The restore completed" proves nothing about an
# audit chain. What proves something is verifying the restored chain against heads the
# AUDITORS hold — not heads that came out of the same backup, which a tampered backup
# would carry happily.
#
#   ./alerting-restore-drill.sh <backup-dir> [auditor-heads.json]
set -Eeuo pipefail

backup="${1:?usage: alerting-restore-drill.sh <backup-dir> [auditor-heads.json]}"
auditor_heads="${2:-}"
: "${ALERTING_PYTHON:=/opt/alerting/current/venv/bin/python}"
: "${ALERTING_AUDITOR:=/opt/alerting/current/venv/bin/alerting-auditor}"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

log()  { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "DRILL FAILED: $*"; exit 1; }

command -v "$ALERTING_PYTHON" >/dev/null 2>&1 || fail "interpreter not found: ${ALERTING_PYTHON}"
command -v "$ALERTING_AUDITOR" >/dev/null 2>&1 || fail "auditor CLI not found: ${ALERTING_AUDITOR}"
[ -f "${backup}/alerting.db.gz" ] || fail "no alerting.db.gz in ${backup}"

gunzip -c "${backup}/alerting.db.gz" > "${workdir}/alerting.db"

"$ALERTING_PYTHON" - "${workdir}/alerting.db" <<'PY' || fail "restored copy is not sound"
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as db:
    verdict = db.execute("PRAGMA integrity_check").fetchone()[0]
    if verdict != "ok":
        raise SystemExit(f"integrity_check: {verdict}")
    # If the append-only triggers did not survive, the restored database is writable
    # in ways the original was not — and a restore is exactly when somebody might.
    triggers = db.execute(
        "SELECT COUNT(*) FROM sqlite_master "
        "WHERE type='trigger' AND name LIKE 'audit_log_no_%'"
    ).fetchone()[0]
    if triggers != 2:
        raise SystemExit(f"append-only triggers missing after restore: {triggers}/2")
print("integrity and append-only triggers: ok")
PY

log "verifying the chain inside the restored copy"
"$ALERTING_AUDITOR" verify --db "${workdir}/alerting.db" || fail "chain does not verify"

if [ -n "$auditor_heads" ]; then
    log "verifying against auditor-held heads: ${auditor_heads}"
    "$ALERTING_AUDITOR" pull --db "${workdir}/alerting.db" --out "${workdir}/chain.json"
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
