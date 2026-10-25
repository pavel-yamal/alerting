#!/usr/bin/env bash
# Ключи push для приложения ЛПР (docs/14-approver-app.md, «Push»).
#
#   ./docker/push-keys.sh apns AuthKey_ABC123.p8 <TEAM_ID> <KEY_ID>   # iPhone: APNs
#   ./docker/push-keys.sh fcm  service-account.json                   # Android: FCM
#   ./docker/push-keys.sh show                                        # что настроено
#   ./docker/push-keys.sh off  apns|fcm                               # выключить
#
# Затем ./docker/up.sh — сервер читает ключи при запуске и не стартует с ключом,
# которым нельзя пользоваться (лучше так, чем стенд, который думает, что шлёт).
#
# Ключи лежат во внешнем томе alerting-push-keys, а не в проекте: `up.sh --reset`
# стирает базу и ключи организации, но не их — новый стенд шлёт push с теми же.
# Владелец — uid 10001 (сервер), права 0400: сервер не читает секрет, доступный
# группе или остальным.
set -Eeuo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."

env_file=docker/.env
volume=alerting-push-keys
fail() { printf 'ОШИБКА: %s\n' "$*" >&2; exit 1; }
[[ -f "$env_file" ]] || fail "нет $env_file — сначала ./docker/up.sh"

set_env() { # set_env KEY VALUE: заменить строку в .env или дописать
    if grep -q "^$1=" "$env_file"; then
        sed -i "s|^$1=.*|$1=$2|" "$env_file"
    else
        printf '%s=%s\n' "$1" "$2" >> "$env_file"
    fi
}

put() { # put <файл на хосте> <имя в томе>
    [[ -r "$1" ]] || fail "не читается: $1"
    docker volume create "$volume" >/dev/null
    docker run --rm -v "$volume:/keys" -v "$(readlink -f "$1"):/in:ro" busybox:1.36 \
        sh -c "cp /in /keys/$2 && chown 10001:10001 /keys/$2 && chmod 0400 /keys/$2"
}

case "${1:-}" in
    apns)
        [[ $# -eq 4 ]] || fail "нужно: apns <файл .p8> <TEAM_ID> <KEY_ID>"
        grep -q "BEGIN PRIVATE KEY" "$2" || fail "$2 не похож на ключ .p8 из Apple Developer"
        put "$2" apns.p8
        set_env ALERTING_APNS_TEAM_ID "$3"
        set_env ALERTING_APNS_KEY_ID "$4"
        set_env ALERTING_APNS_KEY_FILE /run/alerting-push/apns.p8
        echo "APNs: ключ $4 команды $3 записан. Применить: ./docker/up.sh"
        ;;
    fcm)
        [[ $# -eq 2 ]] || fail "нужно: fcm <service-account.json>"
        grep -q '"private_key"' "$2" || fail "$2 не похож на JSON сервисного аккаунта Firebase"
        put "$2" fcm.json
        set_env ALERTING_FCM_SERVICE_ACCOUNT_FILE /run/alerting-push/fcm.json
        echo "FCM: сервисный аккаунт записан. Применить: ./docker/up.sh"
        ;;
    off)
        case "${2:-}" in
            apns) set_env ALERTING_APNS_KEY_FILE "" ;;
            fcm) set_env ALERTING_FCM_SERVICE_ACCOUNT_FILE "" ;;
            *) fail "нужно: off apns|fcm" ;;
        esac
        echo "${2} выключен. Применить: ./docker/up.sh"
        ;;
    show)
        grep -E '^ALERTING_(APNS|FCM)_' "$env_file" || echo "push не настроен"
        docker run --rm -v "$volume:/keys:ro" busybox:1.36 ls -ln /keys 2>/dev/null || true
        ;;
    *)
        sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
        exit 2
        ;;
esac
