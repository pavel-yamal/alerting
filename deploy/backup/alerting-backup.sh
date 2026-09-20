#!/usr/bin/env bash
# Back up everything that cannot be regenerated.
#
# Three things, and each matters for a different reason:
#   * the database    — contacts (personal data) and the audit chain
#   * the audit spool — the ONLY copy of entries that never reached the chain
#   * published heads — the tamper-evidence the chain is checked against
#
# The copy is taken through SQLite's online-backup API, not `cp`: with WAL active a
# file copy yields a torn database. It runs through the server's own interpreter
# rather than the sqlite3 CLI, because the venv is on the box by definition and the
# CLI is a separate package that may not be.
set -Eeuo pipefail

: "${ALERTING_DB:?ALERTING_DB is not set}"
: "${ALERTING_BACKUP_DIR:=/var/backups/alerting}"
: "${ALERTING_SPOOL_DIR:=/var/lib/alerting/spool}"
: "${ALERTING_HEADS_DIR:=/var/lib/alerting/heads}"
: "${ALERTING_BACKUP_KEEP_DAYS:=35}"
: "${ALERTING_PYTHON:=/opt/alerting/current/venv/bin/python}"

log()  { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "BACKUP FAILED: $*"; exit 1; }

command -v "$ALERTING_PYTHON" >/dev/null 2>&1 \
    || fail "interpreter not found: ${ALERTING_PYTHON} (set ALERTING_PYTHON)"
[ -f "$ALERTING_DB" ] || fail "database not found: ${ALERTING_DB}"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
target="${ALERTING_BACKUP_DIR}/${stamp}"

# A backup readable by anyone defeats the point: the database holds names, phone
# numbers and wake keys. See docs/08-personal-data.md.
umask 077
mkdir -p "$target"

log "backing up ${ALERTING_DB} -> ${target}"
"$ALERTING_PYTHON" - "$ALERTING_DB" "${target}/alerting.db" <<'PY' || fail "online backup"
import sqlite3
import sys

source, destination = sys.argv[1], sys.argv[2]
with sqlite3.connect(f"file:{source}?mode=ro", uri=True) as src, \
        sqlite3.connect(destination) as dst:
    src.backup(dst)                                   # consistent snapshot of a live DB

# Verify the copy before believing in it. A backup nobody has restored is a hope, and
# this is the cheap half of proving otherwise.
with sqlite3.connect(destination) as check:
    verdict = check.execute("PRAGMA integrity_check").fetchone()[0]
    if verdict != "ok":
        raise SystemExit(f"integrity_check on the copy said: {verdict}")

    entries = check.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    triggers = check.execute(
        "SELECT COUNT(*) FROM sqlite_master "
        "WHERE type='trigger' AND name LIKE 'audit_log_no_%'"
    ).fetchone()[0]
    # If these did not survive, the copy is writable in ways the original is not.
    if triggers != 2:
        raise SystemExit(f"append-only triggers missing from the copy: {triggers}/2")
    print(f"audit entries: {entries}, append-only triggers: {triggers}")
PY

if [ -d "$ALERTING_SPOOL_DIR" ]; then
    cp -a "$ALERTING_SPOOL_DIR" "${target}/spool"
    spooled="$(find "${target}/spool" -type f | wc -l)"
    # A non-empty spool means audit writes were failing. That is a paging matter, not
    # a backup detail, so it is said loudly here as well.
    [ "$spooled" -eq 0 ] || log "WARNING: audit spool is NOT empty (${spooled} file(s))"
fi

[ -d "$ALERTING_HEADS_DIR" ] && cp -a "$ALERTING_HEADS_DIR" "${target}/heads"

gzip -9 "${target}/alerting.db"
log "wrote $(du -sh "$target" | cut -f1) to ${target}"

# Retention. The heads are also supposed to leave this host entirely — the auditors
# hold copies; this is the local safety net, not the tamper-evidence itself.
find "$ALERTING_BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d \
    -mtime "+${ALERTING_BACKUP_KEEP_DAYS}" -exec rm -rf {} + || true

log "backup complete"
