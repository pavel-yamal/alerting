#!/usr/bin/env bash
# Prove that a failover which loses the tail of the audit chain is DETECTED.
#
# This is the check the whole published-head mechanism exists for, and it is worth
# running on its own because a healthy drill cannot exercise it: on a loopback
# standby the replication lag is a few hundred bytes and the measured RPO is 0, so
# `failover-drill.sh` reports a chain that verifies and proves nothing about the case
# that matters. Here the loss is arranged deliberately and exactly.
#
# The method is to sever replication rather than to slow it. Pausing replay does not
# work: promotion replays whatever the standby already received, so nothing is lost.
# What is lost in a real failover is WAL that never ARRIVED, and clearing
# `primary_conninfo` reproduces that precisely -- the walreceiver shuts down, the
# primary keeps committing, and the standby cannot ever catch up.
#
# Expected outcome, and the script fails if it does not happen: the promoted database
# verifies internally -- a shortened hash chain is still a valid hash chain, which is
# exactly why the chain alone cannot catch this -- and fails against the heads
# published out of band.
#
#   HEADS_DIR=var/heads-primary ./lost-tail-check.sh
set -Eeuo pipefail

: "${PGVERSION:=16}"
: "${PRIMARY_CLUSTER:=main}"
: "${STANDBY_CLUSTER:=standby}"
: "${STANDBY_PORT:=5433}"
: "${OWNER:=alerting_owner}"
: "${PGPASSWORD:=devpass}"
: "${ALERTING_PYTHON:=/home/user/alerting/.venv/bin/python}"
: "${HEADS_DIR:=${ALERTING_HEADS_DIR:-}}"
#: How long the primary is left writing with no standby listening.
: "${SEVERED_SECONDS:=5}"
: "${SLOT:=alerting_standby}"
export PGPASSWORD

log()  { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "CHECK FAILED: $*"; exit 1; }

primary_data="/var/lib/postgresql/${PGVERSION}/${PRIMARY_CLUSTER}"
standby_data="/var/lib/postgresql/${PGVERSION}/${STANDBY_CLUSTER}"
pgctl() { su postgres -c "/usr/lib/postgresql/${PGVERSION}/bin/pg_ctl $*"; }

primary_dsn="postgres://${OWNER}:${PGPASSWORD}@127.0.0.1:5432/alerting"
standby_dsn="postgres://${OWNER}:${PGPASSWORD}@127.0.0.1:${STANDBY_PORT}/alerting"
tip() { psql -tAc "SELECT COALESCE(MAX(idx), -1) FROM audit_log" "$1"; }

[ -n "$HEADS_DIR" ] && [ -d "$HEADS_DIR" ] \
    || fail "set HEADS_DIR to the directory the primary publishes its heads to; \
without out-of-band heads this check cannot detect anything, which is the point"
psql -tAc "SELECT 1" "$primary_dsn" >/dev/null || fail "cannot read the primary"
psql -tAc "SELECT 1" "$standby_dsn" >/dev/null || fail "cannot read the standby"

log "=== severing replication (walreceiver off, primary still committing) ==="
su postgres -c "psql -q -p ${STANDBY_PORT} -c \"ALTER SYSTEM SET primary_conninfo = ''\"" \
    >/dev/null
su postgres -c "psql -q -p ${STANDBY_PORT} -tAc 'SELECT pg_reload_conf()'" >/dev/null
sleep "$SEVERED_SECONDS"

primary_tip="$(tip "$primary_dsn")"
standby_tip="$(tip "$standby_dsn")"
log "primary is at ${primary_tip}, standby stalled at ${standby_tip}"
[ "$primary_tip" -gt "$standby_tip" ] \
    || fail "the standby did not fall behind: nothing was written to the primary \
during the ${SEVERED_SECONDS}s window, so there is no lost tail to detect and a pass \
here would mean nothing. Put traffic on the primary -- a drill order, or anything that \
appends to the chain -- and run this again, or raise SEVERED_SECONDS"

log "=== killing the primary and promoting the stale standby ==="
pgctl stop -m immediate -D "$primary_data" >/dev/null 2>&1 || true
pgctl promote -D "$standby_data" >/dev/null 2>&1 \
    || pg_ctlcluster "$PGVERSION" "$STANDBY_CLUSTER" promote >/dev/null
for _ in $(seq 1 120); do
    state="$(psql -tAc "SELECT pg_is_in_recovery()" "$standby_dsn" 2>/dev/null || echo error)"
    [ "$state" = "f" ] && break
    sleep 0.25
done
[ "${state:-}" = "f" ] || fail "standby did not leave recovery"
log "lost $((primary_tip - $(tip "$standby_dsn"))) audit entries"

log "=== the chain alone: does it notice? ==="
if "$ALERTING_PYTHON" -m alerting.clients.auditor_cli verify \
        --dsn "$standby_dsn" --ignore-heads >/dev/null; then
    log "no -- and it should not. A truncated hash chain is a valid hash chain."
else
    fail "the linkage check failed, which means something other than truncation broke"
fi

log "=== against the heads published out of band: does it notice? ==="
if "$ALERTING_PYTHON" -m alerting.clients.auditor_cli verify \
        --dsn "$standby_dsn" --heads-dir "$HEADS_DIR"; then
    fail "the lost tail went UNDETECTED. The published heads are not doing their job; \
check that they are written outside the database and are not being pruned."
fi
log "yes. The gap is detected, and named."
log "OK -- a failover that loses the tail cannot pass verification unnoticed."

# The standby is deliberately ruined by this point: promoted, severed from its
# primary, and short of a tail its published heads know about. It is not a replica
# any more and must not be left looking like one, so it is dropped rather than
# reattached. Rebuild it from the restored primary with standby-setup.sh.
log "=== restoring the original topology ==="
pg_ctlcluster "$PGVERSION" "$PRIMARY_CLUSTER" start >/dev/null 2>&1 || true
until psql -tAc "SELECT 1" "$primary_dsn" >/dev/null 2>&1; do sleep 0.5; done
pg_ctlcluster "$PGVERSION" "$STANDBY_CLUSTER" stop >/dev/null 2>&1 || true
pg_dropcluster "$PGVERSION" "$STANDBY_CLUSTER" >/dev/null 2>&1 || true
su postgres -c "psql -q -p 5432 -tAc \"SELECT pg_drop_replication_slot('${SLOT}') \
    WHERE EXISTS (SELECT 1 FROM pg_replication_slots \
                  WHERE slot_name='${SLOT}' AND NOT active)\"" >/dev/null 2>&1 || true
log "primary is back; rebuild the standby with standby-setup.sh"
