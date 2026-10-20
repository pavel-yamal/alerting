#!/bin/sh
# Генерирует пароли и DSN один раз, при первом запуске. Повторный запуск ничего не
# меняет: существующие файлы не перезаписываются.
#
# Каждый файл кладётся в свой том и принадлежит тому, кто его читает:
#   /db     — uid 999 (postgres): пароли ролей для начальной настройки базы;
#   /owner  — uid 10001: DSN владельца, только для миграций и org-init;
#   /app    — uid 10001: DSN роли приложения (и ключ подписи голов от org-init).
# Сервер никогда не видит DSN владельца — это и есть разделение ролей.
set -eu

gen() { head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

put() { # put <файл> <uid> <содержимое>
    [ -s "$1" ] && return 0
    umask 077
    printf '%s' "$3" > "$1"
    chown "$2:$2" "$1"
    chmod 0400 "$1"
    echo "created $1"
}

if [ ! -s /db/postgres-password ]; then
    put /db/postgres-password 999 "$(gen)"
fi
if [ ! -s /db/owner-password ]; then
    put /db/owner-password 999 "$(gen)"
fi
if [ ! -s /db/app-password ]; then
    put /db/app-password 999 "$(gen)"
fi

owner_pw=$(cat /db/owner-password)
app_pw=$(cat /db/app-password)
put /owner/dsn 10001 "postgres://alerting_owner:${owner_pw}@db:5432/alerting"
put /app/dsn 10001 "postgres://alerting_app:${app_pw}@db:5432/alerting"
chown 10001:10001 /owner /app
chmod 0700 /owner /app
