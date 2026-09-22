#!/usr/bin/env bash
# Узел резервной базы: PostgreSQL и потоковая репликация с основной.
#
#   REPL_PASSWORD=… ./db-standby.sh
#
# Запускается НА РЕЗЕРВНОЙ машине, после того как основная поднята и пускает по сети.
set -Eeuo pipefail
. "$(dirname "$(readlink -f "$0")")/lib.sh"

require_root
load_inventory
: "${REPL_PASSWORD:?REPL_PASSWORD не задан}"

pgv="$ALERTING_PGVERSION"

log "=== резервная база (${ALERTING_DB_STANDBY_ADDR}) <- ${ALERTING_DB_PRIMARY_ADDR} ==="

log "ставлю PostgreSQL"
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    "postgresql-${pgv}" "postgresql-client-${pgv}" >/dev/null

# Кластер, созданный пакетом, резерву не нужен: standby-setup.sh делает свой
# базовой копией с основной. Оставленный рядом пустой кластер на 5432 — это
# машина, на которой два PostgreSQL и непонятно, к какому из них подключается узел.
if pg_lsclusters | awk '{print $1" "$2}' | grep -qx "${pgv} main"; then
    log "убираю пустой кластер main, созданный пакетом"
    pg_dropcluster "$pgv" main --stop
fi

# Проверить, что основная вообще пускает, до того как начинать базовую копию: иначе
# ошибка вылезет из середины pg_basebackup, где её труднее прочитать.
log "проверяю доступ к основной"
PGPASSWORD="$REPL_PASSWORD" psql -h "$ALERTING_DB_PRIMARY_ADDR" -p 5432 \
    -U alerting_repl -d postgres -tAc "SELECT 1" >/dev/null \
    || fail "роль alerting_repl не проходит на ${ALERTING_DB_PRIMARY_ADDR}. \
Проверьте pg_hba и firewall на основной."

# Резерв на выделенной машине стоит на обычном 5432: порт 5433 был нужен только
# тогда, когда обе базы делили один хост.
log "базовая копия"
PGVERSION="$pgv" \
PRIMARY_HOST="$ALERTING_DB_PRIMARY_ADDR" \
PRIMARY_SSH="${ALERTING_DB_PRIMARY_SSH:-}" \
REPL_PASSWORD="$REPL_PASSWORD" \
    "${REPO_ROOT}/deploy/postgres/standby-setup.sh" main 5432

# listen_addresses в скопированном конфиге — адрес ОСНОВНОЙ: базовая копия
# копирует и постгресовые настройки тоже. Резерв с чужим адресом не поднимется,
# и это тот случай, когда ошибка выглядит как «порт занят» и ищется часами.
conf_dir="/etc/postgresql/${pgv}/main"
if [ -d "$conf_dir" ]; then
    install -d -m 0755 "${conf_dir}/conf.d"
    sed "s|${ALERTING_DB_PRIMARY_ADDR}|${ALERTING_DB_STANDBY_ADDR}|" \
        "${REPO_ROOT}/deploy/postgres/postgresql.alerting.conf" \
        > "${conf_dir}/conf.d/alerting.conf"
    chown postgres:postgres "${conf_dir}/conf.d/alerting.conf"
    grep -qE "^\s*include_dir\s*=\s*'conf\.d'" "${conf_dir}/postgresql.conf" \
        || echo "include_dir = 'conf.d'" >> "${conf_dir}/postgresql.conf"
fi

log "=== резерв поднят ==="
log "Проверить с основной:  SELECT * FROM pg_stat_replication;"
log "Проверить метрикой:    alerting_replication_standbys = 1,"
log "                       alerting_replication_lag_unknown = 0"
log ""
log "Учение переключения запускается с любой машины, где есть ssh на обе базы:"
log "  PRIMARY_SSH=${ALERTING_DB_PRIMARY_SSH} STANDBY_SSH=${ALERTING_DB_STANDBY_SSH} \\"
log "  PRIMARY_HOST=${ALERTING_DB_PRIMARY_ADDR} STANDBY_HOST=${ALERTING_DB_STANDBY_ADDR} \\"
log "  STANDBY_PORT=5432 STANDBY_CLUSTER=main \\"
log "  deploy/postgres/failover-drill.sh"
