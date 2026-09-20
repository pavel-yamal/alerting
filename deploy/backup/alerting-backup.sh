#!/usr/bin/env bash
# Back up everything that cannot be regenerated.
#
# Three things, and each matters for a different reason:
#   * the database    — contacts (personal data) and the audit chain
#   * the audit spool — the ONLY copy of entries that never reached the chain
#   * published heads — the tamper-evidence the chain is checked against
#
# `pg_dump -Fc` takes a consistent snapshot of a running database without blocking
# writers, which matters here: this runs nightly against a node that must stay able
# to dispatch an order throughout. The custom format is what `pg_restore` needs for a
# selective restore, and it compresses on the way out.
#
# It dumps as the OWNER role, because a dump has to include the append-only triggers
# and the grants — the two things that make the restored copy as locked down as the
# original. The application role could not read them.
set -Eeuo pipefail

: "${ALERTING_DSN_FILE:?ALERTING_DSN_FILE is not set (owner role)}"
: "${ALERTING_BACKUP_DIR:=/var/backups/alerting}"
: "${ALERTING_SPOOL_DIR:=/var/lib/alerting/spool}"
: "${ALERTING_HEADS_DIR:=/var/lib/alerting/heads}"
: "${ALERTING_BACKUP_KEEP_DAYS:=35}"
: "${ALERTING_PG_BIN:=/usr/lib/postgresql/16/bin}"

log()  { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "BACKUP FAILED: $*"; exit 1; }

[ -r "$ALERTING_DSN_FILE" ] || fail "DSN file not readable: ${ALERTING_DSN_FILE}"
dsn="$(cat "$ALERTING_DSN_FILE")"
[ -x "${ALERTING_PG_BIN}/pg_dump" ] || fail "pg_dump not found in ${ALERTING_PG_BIN}"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
target="${ALERTING_BACKUP_DIR}/${stamp}"

# A backup readable by anyone defeats the point: the database holds names, phone
# numbers and wake keys. See docs/08-personal-data.md.
umask 077
mkdir -p "$target"

log "dumping database -> ${target}/alerting.dump"
"${ALERTING_PG_BIN}/pg_dump" --format=custom --compress=9 --no-password \
    --file="${target}/alerting.dump" "$dsn" || fail "pg_dump"

# Verify the dump before believing in it. A backup nobody has restored is a hope, and
# reading the archive's own table of contents is the cheap half of proving otherwise.
# The expensive half is the quarterly restore drill; see alerting-restore-drill.sh.
toc="$("${ALERTING_PG_BIN}/pg_restore" --list "${target}/alerting.dump")" \
    || fail "the dump is not readable by pg_restore"

for object in audit_log_append_only audit_log_no_update audit_log_no_delete audit_log_no_truncate; do
    grep -q -- "$object" <<<"$toc" \
        || fail "the dump does not contain ${object}; a restore would not be append-only"
done
log "dump contains the audit table and all three append-only guards"

if [ -d "$ALERTING_SPOOL_DIR" ]; then
    cp -a "$ALERTING_SPOOL_DIR" "${target}/spool"
    spooled="$(find "${target}/spool" -type f | wc -l)"
    # A non-empty spool means audit writes were failing. That is a paging matter, not
    # a backup detail, so it is said loudly here as well.
    [ "$spooled" -eq 0 ] || log "WARNING: audit spool is NOT empty (${spooled} file(s))"
fi

[ -d "$ALERTING_HEADS_DIR" ] && cp -a "$ALERTING_HEADS_DIR" "${target}/heads"

log "wrote $(du -sh "$target" | cut -f1) to ${target}"

# Retention. The heads are also supposed to leave this host entirely — the auditors
# hold copies; this is the local safety net, not the tamper-evidence itself.
find "$ALERTING_BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d \
    -mtime "+${ALERTING_BACKUP_KEEP_DAYS}" -exec rm -rf {} + || true

log "backup complete"
