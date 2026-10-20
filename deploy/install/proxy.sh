#!/usr/bin/env bash
# Узел nginx: TLS, конфигурация, allow-списки.
#
#   CERT_DIR=/path/к/сертификатам ./proxy.sh
#
# CERT_DIR должен содержать fullchain.pem и server.key — от make-ca.sh на стенде или
# от корпоративного УЦ в бою.
set -Eeuo pipefail
. "$(dirname "$(readlink -f "$0")")/lib.sh"

require_root
load_inventory
: "${CERT_DIR:?CERT_DIR не задан: каталог с fullchain.pem и server.key}"
[ -r "${CERT_DIR}/fullchain.pem" ] || fail "нет ${CERT_DIR}/fullchain.pem"
[ -r "${CERT_DIR}/server.key" ]    || fail "нет ${CERT_DIR}/server.key"

log "=== прокси (${ALERTING_PROXY_ADDR}) ==="

log "ставлю nginx"
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx >/dev/null

log "сертификаты"
install -d -o root -g root -m 0750 /etc/ssl/alerting
install -o root -g root -m 0644 "${CERT_DIR}/fullchain.pem" /etc/ssl/alerting/fullchain.pem
install -o root -g root -m 0400 "${CERT_DIR}/server.key"    /etc/ssl/alerting/privkey.pem

log "конфигурация"
install -m 0644 "${REPO_ROOT}/deploy/nginx/alerting-tls-params.conf" /etc/nginx/conf.d/
render "${REPO_ROOT}/deploy/nginx/alerting.conf" /etc/nginx/conf.d/alerting.conf 0644

# Имя хоста render не трогает: он подставляет адреса, а не имена. Адреса узлов, в том
# числе прибитый к одному узлу proxy_pass для метрик, он уже подставил — эндпоинт
# метрик приколочен намеренно, потому что значения, зависящие от узла (держит ли ОН
# блокировку лидера, в recovery ли ЕГО база, что видят ЕГО зонды каналов), при
# round-robin прыгали бы между опросами (ADR 0009).
sed -i "s|alerting\\.example\\.internal|${ALERTING_FQDN}|g" /etc/nginx/conf.d/alerting.conf
assert_rendered /etc/nginx/conf.d/alerting.conf

# nginx -t первый раз в жизни этого конфига: он писался в контейнере, где nginx не
# установлен, и до сих пор не проверялся ничем (docs/10-failover.md §1).
log "проверяю конфигурацию"
nginx -t || fail "nginx -t не прошёл"

# Дефолтный сайт Debian отвечает на всё, что не совпало с server_name, и показывает
# страницу «Welcome to nginx». На машине, единственная задача которой — не отвечать
# посторонним, это ровно то, чего быть не должно.
rm -f /etc/nginx/sites-enabled/default

nginx -t || fail "nginx -t не прошёл после удаления сайта по умолчанию"
systemctl enable nginx
systemctl reload nginx 2>/dev/null || systemctl restart nginx

log "=== прокси готов ==="
log "Проверить снаружи:"
log "  curl --cacert ca.crt https://${ALERTING_FQDN}/v1/healthz"
log "  curl --cacert ca.crt https://${ALERTING_FQDN}/v1/readyz     # с адреса из PROXY_NET"
log "Оба узла должны отвечать: least_conn раскидывает, proxy_next_upstream уводит"
log "запрос со второго узла, если первый отвечает 503 (не готов к записи)."
