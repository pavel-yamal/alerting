#!/usr/bin/env bash
# Узел приложения: релиз, venv, юниты, конфигурация, секреты.
#
#   NODE=app1 ./app-node.sh
#
# Не запускает сервис. Запуск — отдельное решение человека, после того как
# `alerting-server --check` прошёл и бандлы организации опубликованы: узел, поднятый
# до публикации справочника, будет честно отвечать «не готов», и это правильно, но
# отлаживать в этот момент удобнее руками.
set -Eeuo pipefail
. "$(dirname "$(readlink -f "$0")")/lib.sh"

require_root
load_inventory
: "${NODE:?NODE не задан: app1 или app2}"

case "$NODE" in
    app1) bind_addr="$ALERTING_APP1_ADDR" ;;
    app2) bind_addr="$ALERTING_APP2_ADDR" ;;
    *) fail "NODE должен быть app1 или app2, а не '${NODE}'" ;;
esac

release="${RELEASE:-$(cd "$REPO_ROOT" && git describe --always --dirty 2>/dev/null || date -u +%Y%m%dT%H%M%SZ)}"
target="/opt/alerting/releases/${release}"

log "=== узел ${NODE} (${bind_addr}), релиз ${release} ==="

ensure_user
ensure_dirs

log "ставлю системные пакеты"
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    python3 python3-venv python3-dev build-essential libpq5 curl >/dev/null

# Релиз — каталог с версией, `current` — симлинк на него. Так обещает
# docs/09-deployment.md §3, и так устроен откат: перестановка симлинка и перезапуск,
# без выкачивания чего бы то ни было в момент, когда всё уже сломано.
log "раскладываю релиз в ${target}"
install -d -m 0755 /opt/alerting/releases
rm -rf "${target}.partial"
mkdir -p "${target}.partial"
tar -C "$REPO_ROOT" \
    --exclude=.git --exclude=.venv --exclude=var --exclude='*.pyc' \
    --exclude=__pycache__ --exclude=deploy/inventory.env \
    -cf - . | tar -C "${target}.partial" -xf -

log "собираю venv"
python3 -m venv "${target}.partial/venv"
"${target}.partial/venv/bin/pip" install -q --upgrade pip
"${target}.partial/venv/bin/pip" install -q "${target}.partial"

# Готовый каталог появляется целиком или не появляется: половина релиза, на которую
# уже показывает `current`, — это узел, который не стартует и не откатывается.
rm -rf "$target"
mv "${target}.partial" "$target"
ln -sfn "$target" /opt/alerting/current.new
mv -Tf /opt/alerting/current.new /opt/alerting/current
log "  /opt/alerting/current -> ${target}"

# --- конфигурация -------------------------------------------------------------
log "конфигурация"
if [ -e /etc/alerting/alerting.env ]; then
    log "  /etc/alerting/alerting.env уже есть, не трогаю"
else
    install -o root -g alerting -m 0640 \
        "${REPO_ROOT}/deploy/env/alerting.env.example" /etc/alerting/alerting.env
    log "  /etc/alerting/alerting.env создан из образца — ЗАПОЛНИТЕ ALERTING_ROOT_PUBKEY"
fi

# Значения, которые знает инвентарь, проставляются здесь, а не оставляются человеку:
# каждое из них расходится тихо. `sed -i` по конкретным ключам, а не перезапись
# файла целиком — то, что оператор уже вписал руками, должно пережить переустановку.
set_env_key() {
    local key="$1" value="$2"
    if grep -qE "^${key}=" /etc/alerting/alerting.env; then
        sed -i "s|^${key}=.*|${key}=${value}|" /etc/alerting/alerting.env
    else
        printf '%s=%s\n' "$key" "$value" >> /etc/alerting/alerting.env
    fi
}
set_env_key ALERTING_ORG "$ALERTING_ORG"
set_env_key ALERTING_ORG_LABEL "$ALERTING_ORG_LABEL"
set_env_key ALERTING_NODE_ID "$NODE"
set_env_key ALERTING_WORDLIST /opt/alerting/current/config/wordlist.ru.txt

# Заглушки каналов. На стенде без них узел не стартует вовсе — доставлять нечем.
# В боевом контуре флаг не ставится: юнит обязан отказаться подниматься, если
# лестница эскалации называет каналы, которые отчитаются о доставке, ничего не
# отправив (docs/09-deployment.md §0).
if [ "$ALERTING_CONTOUR" = "staging" ]; then
    set_env_key ALERTING_ALLOW_STUB_CHANNELS 1
    warn "ALERTING_ALLOW_STUB_CHANNELS=1 — контур стенда. Оповещение доходит ТОЛЬКО"
    warn "до тех, у кого открыто приложение; push, SMS, голос и сирена не отправляют"
    warn "ничего. Напечатанный резервный порядок — основной способ, а не запасной."
else
    sed -i '/^ALERTING_ALLOW_STUB_CHANNELS=/d' /etc/alerting/alerting.env
fi

if [ -e /etc/alerting/escalation.yaml ]; then
    log "  /etc/alerting/escalation.yaml уже есть, не трогаю"
else
    install -o root -g root -m 0644 \
        "${REPO_ROOT}/config/escalation.example.yaml" /etc/alerting/escalation.yaml
fi

# --- юниты --------------------------------------------------------------------
log "юниты systemd"
sed "s|--host 10.0.10.11|--host ${bind_addr}|; \
     s|--forwarded-allow-ips 10.0.10.0/24|--forwarded-allow-ips ${ALERTING_PROXY_NET}|" \
    "${REPO_ROOT}/deploy/systemd/alerting.service" > /etc/systemd/system/alerting.service
grep -q -- "--host ${bind_addr}" /etc/systemd/system/alerting.service \
    || fail "адрес привязки не подставился в alerting.service"
install -m 0644 "${REPO_ROOT}/deploy/systemd/alerting-migrate.service" /etc/systemd/system/
install -m 0644 "${REPO_ROOT}/deploy/systemd/alerting-artifacts-backup.service" \
    /etc/systemd/system/
install -m 0644 "${REPO_ROOT}/deploy/systemd/alerting-artifacts-backup.timer" \
    /etc/systemd/system/
systemctl daemon-reload

log "=== узел ${NODE} подготовлен ==="
log ""
log "Осталось, и это не автоматизируется намеренно:"
log "  1. Положить секреты (см. deploy/env/credentials.README.md):"
log "       /etc/alerting/credentials/dsn-app     0400 root:root"
log "       /etc/alerting/credentials/dsn-owner   0400 root:root"
log "       /etc/alerting/credentials/server-key  0400 root:root"
log "  2. Вписать ALERTING_ROOT_PUBKEY в /etc/alerting/alerting.env и СВЕРИТЬ его"
log "     вне канала с тем, что держат хранители: подменённый корневой ключ"
log "     пропускает поддельный справочник, и проверка этого не заметит."
log "  3. Проверить конфигурацию, не запуская сервис:"
log "       /opt/alerting/current/venv/bin/alerting-server --check"
log "  4. systemctl enable --now alerting alerting-artifacts-backup.timer"
