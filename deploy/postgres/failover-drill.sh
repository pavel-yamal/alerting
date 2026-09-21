#!/usr/bin/env bash
# Failover drill: kill the primary, promote the standby, and MEASURE.
#
# The measurement is the point. Phase 7 (active/active) is worth doing only if
# active/passive cannot meet the recovery objective, and that is a question about
# numbers, not opinions. This script produces them:
#
#   RTO -- seconds from the primary dying to a node on the promoted standby
#          answering `readyz: ready`.
#   RPO -- audit-chain entries lost. Replication is asynchronous by design
#          (docs/adr/0009), so a committed entry the standby had not received is
#          gone. This counts exactly how many.
#   chain -- whether the promoted database still verifies, and whether the last
#          head published by the old primary still matches. A lost tail is not
#          prevented; it is DETECTED, by the mechanism built for it.
#
# It restores the original topology afterwards, so it can be run again.
#
#   ./failover-drill.sh
set -Eeuo pipefail

: "${PGVERSION:=16}"
: "${PRIMARY_CLUSTER:=main}"
: "${STANDBY_CLUSTER:=standby}"
: "${STANDBY_PORT:=5433}"
: "${OWNER:=alerting_owner}"
: "${PGPASSWORD:=devpass}"
: "${ALERTING_PYTHON:=/home/user/alerting/.venv/bin/python}"
# A node already pointed at the standby. While the standby is in recovery it answers
# `readyz: 503 writable=false`; the moment it can write, it goes green. That
# transition is the RTO an operator actually cares about -- the database being
# promoted is only the first half.
: "${READYZ_URL:=}"
# Where the primary wrote its signed heads. See the chain check below for why these,
# and not the database's own `heads` table, are the ones that mean anything here.
: "${HEADS_DIR:=${ALERTING_HEADS_DIR:-}}"
: "${SLOT:=alerting_standby}"
# A port nothing is configured to use, so the resurrected old primary can be
# questioned without its former clients finding it again. See the RPO step below.
: "${ISOLATED_PORT:=5434}"
export PGPASSWORD

log()  { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "DRILL FAILED: $*"; exit 1; }

primary_data="/var/lib/postgresql/${PGVERSION}/${PRIMARY_CLUSTER}"
# Debian keeps the configuration under /etc and the data under /var, so a postmaster
# started straight from the data directory cannot find its own postgresql.conf.
# pg_ctlcluster supplies this; pg_ctl has to be told.
primary_conf="/etc/postgresql/${PGVERSION}/${PRIMARY_CLUSTER}/postgresql.conf"
primary_log="/var/log/postgresql/postgresql-${PGVERSION}-${PRIMARY_CLUSTER}.log"
standby_data="/var/lib/postgresql/${PGVERSION}/${STANDBY_CLUSTER}"
# `su -c` runs a shell, so everything here is re-parsed once. An argument that must
# survive as a single word -- `-o` and its whole option string -- therefore needs
# literal quotes inside it at the call site, not just around it: the outer quoting is
# gone by the time the inner shell reads the line. Without them pg_ctl received `-o
# -c` and a scatter of stray words, and failed instantly.
pgctl() { su postgres -c "/usr/lib/postgresql/${PGVERSION}/bin/pg_ctl $*"; }

primary_dsn="postgres://${OWNER}:${PGPASSWORD}@127.0.0.1:5432/alerting"
standby_dsn="postgres://${OWNER}:${PGPASSWORD}@127.0.0.1:${STANDBY_PORT}/alerting"

tip() { psql -tAc "SELECT COALESCE(MAX(idx), -1) FROM audit_log" "$1"; }

pg_lsclusters | awk '{print $2}' | grep -qx "$STANDBY_CLUSTER" \
    || fail "no standby cluster '${STANDBY_CLUSTER}'; run standby-setup.sh first"

log "=== before ==="
psql -tAc "SELECT 1" "$primary_dsn" >/dev/null || fail "cannot read the primary"
lag="$(psql -tAc "SELECT COALESCE(pg_wal_lsn_diff(sent_lsn, replay_lsn), 0) \
    FROM pg_stat_replication LIMIT 1" "$primary_dsn")"
log "replication lag: ${lag:-unknown} bytes"

# `-m immediate`, not a graceful stop. A clean shutdown lets the walsender finish
# handing the standby everything it has, which would measure an orderly maintenance
# switchover and report RPO 0 -- the number an operator wants to believe. The failure
# being drilled is a machine that died, so the drill kills it like one.
# Read from the standby one instant before the kill, because the total RPO on its own
# does not say WHERE the entries went, and the two places mean different things:
#
#   never arrived        -- asynchronous replication, the price named in ADR 0009.
#                           Shrinking it means making the primary wait, which is the
#                           trade this system refuses.
#   arrived, not applied -- received WAL that promotion did not replay. That is a
#                           property of how the standby is promoted, not of the
#                           replication mode, and it is fixable without touching the
#                           primary's latency at all.
#
# The first drill reported 1724 lost entries against a replication lag reading of 288
# bytes, and those two numbers cannot both describe the same gap.
standby_before="$(tip "$standby_dsn" 2>/dev/null || echo "")"

log "=== killing the primary (immediate, as a crash) ==="
failed_at="$(date +%s.%N)"
# pg_ctl, not pg_ctlcluster: asked for `-m immediate --force`, pg_ctlcluster logged
# "received fast shutdown request" and ran a clean shutdown checkpoint. `--force`
# overrides the mode. So the drill was measuring an orderly switchover -- with the
# walsender given time to hand over everything it had -- while its own output said
# "killing the primary". pg_ctl takes the mode literally.
pgctl stop -m immediate -D "$primary_data" >/dev/null 2>&1 || true

log "=== promoting the standby ==="
pgctl promote -D "$standby_data" >/dev/null 2>&1 \
    || pg_ctlcluster "$PGVERSION" "$STANDBY_CLUSTER" promote >/dev/null

for _ in $(seq 1 120); do
    state="$(psql -tAc "SELECT pg_is_in_recovery()" "$standby_dsn" 2>/dev/null || echo error)"
    [ "$state" = "f" ] && break
    sleep 0.25
done
[ "${state:-}" = "f" ] || fail "standby did not leave recovery"
promoted_at="$(date +%s.%N)"

app_rto=""
if [ -n "$READYZ_URL" ]; then
    for _ in $(seq 1 240); do
        if curl -sf -m 1 -o /dev/null "$READYZ_URL"; then
            app_rto="$(awk -v a="$failed_at" -v b="$(date +%s.%N)" 'BEGIN{printf "%.2f", b-a}')"
            break
        fi
        sleep 0.25
    done
    [ -n "$app_rto" ] || log "WARNING: the node never became ready; RTO is not bounded"
fi

# The standby's tip AT PROMOTION, read before anything is written to it. Everything
# the old primary committed beyond this is what the failover lost.
after="$(tip "$standby_dsn")" || fail "cannot read the promoted database"
rto="$(awk -v a="$failed_at" -v b="$promoted_at" 'BEGIN{printf "%.2f", b-a}')"

# RPO can only be measured against what the dead primary actually had, so the old
# primary is brought back and asked. Two things about how, both learned by getting a
# wrong number first:
#
#   Not before the kill. Writes continue in the gap between the read and the stop, so
#   the answer comes out negative.
#
#   On a SPARE PORT, not its usual one. Everything that was writing to the primary
#   reconnects the instant it answers on 5432 -- psycopg's pool does it by itself,
#   and the audit service is built never to raise on a database error, so a writer
#   does not even stop. The previous version read the tip two seconds after starting
#   it normally, and two seconds of entries written AFTER the failover counted as
#   lost. That measurement was reading its own load generator: it reported 1682
#   entries lost against a replication lag of 0 bytes, and both cannot be true.
log "=== measuring what was lost ==="
isolated_dsn="postgres://${OWNER}:${PGPASSWORD}@127.0.0.1:${ISOLATED_PORT}/alerting"
# pg_ctl again, and for a second reason: pg_ctlcluster checks readiness against the
# port in the config file, so a start on any other port is reported as a failure
# while the postmaster is in fact up and serving -- and `pg_lsclusters` then prints
# "online" on a port nothing is listening on.
# `-l` matters here beyond tidiness: without it the postmaster inherits pg_ctl's
# stderr and holds it open, so any pipeline reading this script's output never sees
# EOF and hangs after the drill has otherwise finished.
pgctl start -w -D "$primary_data" -l "$primary_log" \
    -o "'-c config_file=${primary_conf} -p ${ISOLATED_PORT}'" >/dev/null 2>&1 \
    || fail "could not restart the old primary on port ${ISOLATED_PORT}"
before="$(tip "$isolated_dsn")" || fail "cannot re-read the old primary"
rpo=$((before - after))
pgctl stop -D "$primary_data" >/dev/null 2>&1 || true

log "=== results ==="
log "RTO (database): ${rto}s   from primary down to standby accepting writes"
[ -n "$app_rto" ] && log "RTO (service) : ${app_rto}s   until a node answered readyz: ready"
log "RPO           : ${rpo} audit entries lost (old primary had ${before}, standby had ${after})"
if [ -n "$standby_before" ]; then
    log "  of which never reached the standby        : $((before - standby_before))"
    log "  of which reached it but were not replayed : $((standby_before - after))"
fi

# Against the heads published OUT OF BAND, not the ones in the database. That
# distinction is the whole mechanism: a head the primary wrote is a row in the same
# database whose tail was just lost, so it went with it, and the shortened chain
# verifies against what is left of itself without complaint. The file on disk (in
# production: in three auditors' inboxes) is what a lost tail cannot reach.
log "=== is the chain still sound? ==="
heads_flag=()
if [ -n "$HEADS_DIR" ] && [ -d "$HEADS_DIR" ]; then
    heads_flag=(--heads-dir "$HEADS_DIR")
else
    log "WARNING: no ALERTING_HEADS_DIR; checking against the promoted database's own"
    log "         heads, which cannot detect a lost tail. This is a weaker check."
fi
if "$ALERTING_PYTHON" -m alerting.clients.auditor_cli verify \
        --dsn "$standby_dsn" "${heads_flag[@]+"${heads_flag[@]}"}"; then
    log "chain verifies on the promoted database"
    chain="ok"
else
    log "CHAIN DOES NOT VERIFY on the promoted database -- this is the case the"
    log "published heads exist for. Record the gap; do not paper over it."
    chain="broken"
fi

log "=== restoring the original topology ==="
pg_ctlcluster "$PGVERSION" "$PRIMARY_CLUSTER" start >/dev/null 2>&1 || true
until psql -tAc "SELECT 1" "$primary_dsn" >/dev/null 2>&1; do sleep 0.5; done
pg_ctlcluster "$PGVERSION" "$STANDBY_CLUSTER" stop >/dev/null 2>&1 || true
pg_dropcluster "$PGVERSION" "$STANDBY_CLUSTER" >/dev/null 2>&1 || true
# As postgres, not as the owner role: dropping a slot needs the REPLICATION
# attribute, and the owner does not have it -- so this silently did nothing, and the
# slot survived every drill, making the primary retain WAL for a standby that no
# longer existed.
su postgres -c "psql -q -p 5432 -tAc \"SELECT pg_drop_replication_slot('${SLOT}') \
    WHERE EXISTS (SELECT 1 FROM pg_replication_slots \
                  WHERE slot_name='${SLOT}' AND NOT active)\"" >/dev/null 2>&1 || true
log "primary is back; rebuild the standby with standby-setup.sh"

printf '\nRTO_DB_SECONDS=%s\nRTO_SERVICE_SECONDS=%s\nRPO_ENTRIES=%s\nCHAIN=%s\n' \
    "$rto" "${app_rto:-unmeasured}" "$rpo" "$chain"
