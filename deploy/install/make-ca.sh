#!/usr/bin/env bash
# Свой УЦ и сертификат для СТЕНДА.
#
#   ./make-ca.sh <каталог-вывода>
#
# Только для стенда, и скрипт на этом настаивает: при ALERTING_CONTOUR=production он
# отказывается работать. Боевой контур получает сертификат от корпоративного УЦ —
# внутренняя система почти наверняка живёт там, а не в ACME (docs/09-deployment.md §2).
#
# Что здесь важно понимать про доверие: этот УЦ защищает ТРАНСПОРТ и ничего больше.
# Подлинность приказа он не удостоверяет и удостоверять не может — её проверяет
# клиент по подписи Ed25519 и закреплённому корневому ключу организации. Скомпро-
# метированный TLS не даёт подделать приказ; он даёт читать и задерживать.
set -Eeuo pipefail
. "$(dirname "$(readlink -f "$0")")/lib.sh"

out="${1:?usage: make-ca.sh <каталог-вывода>}"
load_inventory

[ "$ALERTING_CONTOUR" = "staging" ] \
    || fail "ALERTING_CONTOUR=${ALERTING_CONTOUR}: самоподписанный УЦ для боевого \
контура не годится. Возьмите сертификат у корпоративного УЦ."

install -d -m 0700 "$out"
cd "$out"

if [ -e ca.key ]; then
    log "УЦ уже есть в ${out}, выпускаю только сертификат узла"
else
    log "корневой УЦ стенда"
    openssl genrsa -out ca.key 4096 2>/dev/null
    chmod 0400 ca.key
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 1825 \
        -subj "/CN=alerting staging CA/O=${ALERTING_ORG_LABEL}" -out ca.crt 2>/dev/null
fi

log "сертификат для ${ALERTING_FQDN}"
openssl genrsa -out server.key 2048 2>/dev/null
chmod 0400 server.key
openssl req -new -key server.key -subj "/CN=${ALERTING_FQDN}" -out server.csr 2>/dev/null

# SAN обязателен: браузеры и современные клиенты не смотрят на CN вовсе. Адрес прокси
# добавлен рядом с именем, потому что на стенде к нему ходят и по адресу тоже.
cat > server.ext <<EXT
subjectAltName = DNS:${ALERTING_FQDN}, IP:${ALERTING_PROXY_ADDR}
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EXT

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 825 -sha256 -extfile server.ext 2>/dev/null
cat server.crt ca.crt > fullchain.pem
rm -f server.csr server.ext

log "=== готово, в ${out} ==="
log "  ca.crt        — раздать клиентам стенда как доверенный"
log "  fullchain.pem — на прокси, ssl_certificate"
log "  server.key    — на прокси, ssl_certificate_key (0400)"
log ""
log "ca.key остаётся ЗДЕСЬ и на прокси не едет: кто им владеет, выпишет сертификат"
log "на любое имя. Для стенда это неприятность, для привычки — нет."
