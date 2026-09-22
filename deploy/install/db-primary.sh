#!/usr/bin/env bash
# Узел основной базы: PostgreSQL, три роли, сеть, ночной бэкап.
#
#   ./db-primary.sh
#
# Пароли не придумывает и не печатает: они приходят снаружи, потому что те же
# значения нужны на узлах приложения в файлах DSN, и генерация «на месте» означала бы
# копирование пароля из лога.
#
#   OWNER_PASSWORD=… APP_PASSWORD=… REPL_PASSWORD=… ./db-primary.sh
set -Eeuo pipefail
. "$(dirname "$(readlink -f "$0")")/lib.sh"

require_root
load_inventory
: "${OWNER_PASSWORD:?OWNER_PASSWORD не задан}"
: "${APP_PASSWORD:?APP_PASSWORD не задан}"
: "${REPL_PASSWORD:?REPL_PASSWORD не задан}"

pgv="$ALERTING_PGVERSION"
conf_dir="/etc/postgresql/${pgv}/main"

log "=== основная база (${ALERTING_DB_PRIMARY_ADDR}), PostgreSQL ${pgv} ==="

log "ставлю PostgreSQL"
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    "postgresql-${pgv}" "postgresql-client-${pgv}" >/dev/null
[ -d "$conf_dir" ] || fail "нет ${conf_dir}: кластер main не создан"

# --- роли ---------------------------------------------------------------------
# roles.sql создаёт их и падает, если они уже есть, — это верно для первой
# установки и неверно для повторной. Поэтому существующие роли пропускаются, а
# пароли выставляются отдельно: повторный запуск установщика их обновляет.
if su postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='alerting_owner'\"" \
        | grep -qx 1; then
    log "роли уже есть, обновляю пароли"
    su postgres -c "psql -q -v ON_ERROR_STOP=1" <<SQL
ALTER ROLE alerting_owner PASSWORD '${OWNER_PASSWORD}';
ALTER ROLE alerting_app   PASSWORD '${APP_PASSWORD}';
ALTER ROLE alerting_repl  PASSWORD '${REPL_PASSWORD}';
SQL
else
    log "создаю роли и базу"
    su postgres -c "psql -q -v ON_ERROR_STOP=1 \
        -v owner_password=\"'${OWNER_PASSWORD}'\" \
        -v app_password=\"'${APP_PASSWORD}'\" \
        -v repl_password=\"'${REPL_PASSWORD}'\"" < "${REPO_ROOT}/deploy/postgres/roles.sql"
fi

# --- сеть ---------------------------------------------------------------------
log "настройки и доступ по сети"
install -d -m 0755 "${conf_dir}/conf.d"
render "${REPO_ROOT}/deploy/postgres/postgresql.alerting.conf" \
    "${conf_dir}/conf.d/alerting.conf" 0644
assert_rendered "${conf_dir}/conf.d/alerting.conf"
chown postgres:postgres "${conf_dir}/conf.d/alerting.conf"

# Debian кладёт include_dir в postgresql.conf по умолчанию, но проверить дешевле,
# чем потом искать, почему настройки не применились.
grep -qE "^\s*include_dir\s*=\s*'conf\.d'" "${conf_dir}/postgresql.conf" \
    || echo "include_dir = 'conf.d'" >> "${conf_dir}/postgresql.conf"

# pg_hba дописывается один раз и помечается маркером: файл принадлежит пакету, и
# затирать его целиком значит потерять то, что дистрибутив туда положил.
marker="# >>> alerting"
if grep -qF "$marker" "${conf_dir}/pg_hba.conf"; then
    log "  правила pg_hba уже есть, перезаписываю блок"
    sed -i "/^${marker}\$/,/^# <<< alerting\$/d" "${conf_dir}/pg_hba.conf"
fi
hba_tmp="$(mktemp)"
render "${REPO_ROOT}/deploy/postgres/pg_hba.alerting.conf" "$hba_tmp" 0644
assert_rendered "$hba_tmp"
{ echo "$marker"; cat "$hba_tmp"; echo "# <<< alerting"; } >> "${conf_dir}/pg_hba.conf"
rm -f "$hba_tmp"
chown postgres:postgres "${conf_dir}/pg_hba.conf"

systemctl restart "postgresql@${pgv}-main"
until su postgres -c "pg_isready -q"; do sleep 0.5; done
log "  PostgreSQL слушает ${ALERTING_DB_PRIMARY_ADDR}"

# --- бэкап --------------------------------------------------------------------
log "ночной бэкап"
ensure_user
install -d -o alerting -g alerting -m 0750 /var/backups/alerting
install -d -m 0755 /opt/alerting/releases
# Бэкапу нужен только сам скрипт, не весь релиз: сервера здесь нет.
install -d -m 0755 /opt/alerting/current/deploy/backup
install -m 0755 "${REPO_ROOT}/deploy/backup/alerting-backup.sh" \
    /opt/alerting/current/deploy/backup/
install -m 0755 "${REPO_ROOT}/deploy/backup/alerting-restore-drill.sh" \
    /opt/alerting/current/deploy/backup/
sed "s|ALERTING_PG_BIN=/usr/lib/postgresql/16/bin|ALERTING_PG_BIN=/usr/lib/postgresql/${pgv}/bin|" \
    "${REPO_ROOT}/deploy/systemd/alerting-backup.service" \
    > /etc/systemd/system/alerting-backup.service
install -m 0644 "${REPO_ROOT}/deploy/systemd/alerting-backup.timer" /etc/systemd/system/

install -d -o root -g root -m 0700 /etc/alerting/credentials
write_secret /etc/alerting/credentials/dsn-owner \
    "postgres://alerting_owner:${OWNER_PASSWORD}@127.0.0.1:5432/alerting"
systemctl daemon-reload
systemctl enable --now alerting-backup.timer

log "=== основная база готова ==="
log ""
log "DSN для узлов приложения (положить туда файлами 0400 root:root):"
log "  dsn-app   : postgres://alerting_app:<APP_PASSWORD>@${ALERTING_DB_PRIMARY_ADDR}:5432/alerting"
log "  dsn-owner : postgres://alerting_owner:<OWNER_PASSWORD>@${ALERTING_DB_PRIMARY_ADDR}:5432/alerting"
log "Пароли здесь не печатаются: лог установки читают и пересылают."
log ""
log "Дальше: миграции применит alerting-migrate.service при первом запуске узла."
