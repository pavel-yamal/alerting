#!/usr/bin/env bash
# Build a streaming standby from a running primary.
#
# Asynchronous on purpose, and that is the decision this whole file rests on
# (docs/adr/0009). A synchronous standby would make the primary wait for it on every
# commit -- so a replica that goes down stops the primary dispatching orders, which is
# the worst failure this system has. The price is that a failover can lose the tail of
# the audit chain, and that loss is measured by failover-drill.sh and detected by the
# published heads.
#
# Запускается НА РЕЗЕРВНОЙ машине. На разнесённых хостах это единственный из трёх
# скриптов, которому чужой хост нужен только по сети (pg_basebackup и так ходит по
# TCP) — за одним исключением, отмеченным ниже: сброс залипшего слота делается НА
# ОСНОВНОЙ, и локальным сокетом туда не попасть.
#
#   PRIMARY_HOST=10.0.10.21 REPL_PASSWORD=… ./standby-setup.sh <cluster-name> <port>
set -Eeuo pipefail

cluster="${1:?usage: standby-setup.sh <cluster-name> <port>}"
port="${2:?usage: standby-setup.sh <cluster-name> <port>}"
: "${PGVERSION:=16}"
: "${REPL_USER:=alerting_repl}"
: "${PRIMARY_HOST:=127.0.0.1}"
: "${PRIMARY_PORT:=5432}"
: "${SLOT:=alerting_standby}"
# `su postgres -c` starts a fresh environment, so exporting this in the caller's shell
# is not enough -- it has to be handed to pg_basebackup on its own command line.
# Without it the backup sits forever on a password prompt with nothing to read it.
# A production standby uses a .pgpass file owned by postgres, mode 0600, and never a
# password on a command line where `ps` can see it.
: "${REPL_PASSWORD:=devpass}"

log()  { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
fail() { log "STANDBY SETUP FAILED: $*"; exit 1; }

data="/var/lib/postgresql/${PGVERSION}/${cluster}"
conf="/etc/postgresql/${PGVERSION}/${cluster}"

pg_lsclusters | awk '{print $1" "$2}' | grep -qx "${PGVERSION} ${cluster}" \
    && fail "cluster ${PGVERSION}/${cluster} already exists; drop it first"

log "creating cluster ${PGVERSION}/${cluster} on port ${port}"
pg_createcluster "$PGVERSION" "$cluster" --port "$port" >/dev/null

# A slot left behind by a previous standby is what you find when rebuilding one, and
# it is not harmless: an inactive slot makes the primary retain WAL forever, which
# eventually fills the disk of the node that must never stop dispatching. Dropping it
# is deliberate, and it is safe precisely because the standby it belonged to is gone.
#
# Слот живёт НА ОСНОВНОЙ машине, и раньше эта команда шла в локальный сокет: пока обе
# базы стояли на одном хосте, это и была основная. На разнесённых хостах она молча
# уходила в резерв, где слота нет, — `|| true` проглатывал ошибку, слот на основной
# оставался, и основная копила WAL для резерва, которого больше не существует.
# Поэтому здесь либо SSH на основную (PRIMARY_SSH), либо psql по сети под ролью,
# у которой есть право на слоты.
log "dropping any stale replication slot named ${SLOT} on ${PRIMARY_HOST}"
drop_slot="SELECT pg_drop_replication_slot('${SLOT}') WHERE EXISTS \
    (SELECT 1 FROM pg_replication_slots WHERE slot_name='${SLOT}' AND NOT active)"
if [ -n "${PRIMARY_SSH:-}" ]; then
    ssh -n "$PRIMARY_SSH" "su postgres -c \"psql -q -tAc \\\"${drop_slot}\\\"\"" \
        >/dev/null 2>&1 || true
elif [ "$PRIMARY_HOST" = "127.0.0.1" ] || [ "$PRIMARY_HOST" = "localhost" ]; then
    su postgres -c "psql -q -p ${PRIMARY_PORT} -tAc \"${drop_slot}\"" >/dev/null 2>&1 || true
else
    # Без PRIMARY_SSH остаётся сеть. Роль репликации слот не удалит — для этого нужны
    # права суперпользователя или владельца с REPLICATION, — поэтому если не вышло,
    # об этом надо сказать, а не проглотить: залипший слот съедает диск основной.
    PGPASSWORD="$REPL_PASSWORD" psql -q -h "$PRIMARY_HOST" -p "$PRIMARY_PORT" \
        -U "$REPL_USER" -d postgres -tAc "$drop_slot" >/dev/null 2>&1 \
        || log "WARNING: не удалось проверить слот ${SLOT} на ${PRIMARY_HOST}. \
Если он остался от прежнего резерва и неактивен, основная будет копить WAL до \
заполнения диска. Задайте PRIMARY_SSH или удалите слот вручную."
fi

log "base backup from ${PRIMARY_HOST}:${PRIMARY_PORT} (slot ${SLOT})"
rm -rf "${data:?}"/*
su postgres -c "PGPASSWORD='${REPL_PASSWORD}' \
    /usr/lib/postgresql/${PGVERSION}/bin/pg_basebackup \
    --host=${PRIMARY_HOST} --port=${PRIMARY_PORT} --username=${REPL_USER} \
    --pgdata=${data} --wal-method=stream --write-recovery-conf \
    --slot=${SLOT} --create-slot --checkpoint=fast --progress" \
    || fail "pg_basebackup"

# pg_basebackup copies the primary's postgresql.conf, port included, so the standby
# would try to bind the port the primary already holds.
su postgres -c "echo \"port = ${port}\" >> ${data}/postgresql.auto.conf"
# The standby must be readable: the metrics endpoint and readiness both ask it
# questions, and a node pointed at an unreadable database cannot say why.
su postgres -c "echo 'hot_standby = on' >> ${data}/postgresql.auto.conf"
cp "${conf}/pg_hba.conf" "${data}/pg_hba.conf" 2>/dev/null || true

log "starting standby"
pg_ctlcluster "$PGVERSION" "$cluster" start || fail "standby did not start"

for _ in $(seq 1 30); do
    if su postgres -c "psql -p ${port} -tAc 'SELECT pg_is_in_recovery()'" 2>/dev/null \
        | grep -qx t; then
        log "standby is streaming on port ${port}"
        exit 0
    fi
    sleep 1
done
fail "standby did not reach recovery state"
