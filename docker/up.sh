#!/usr/bin/env bash
# Стенд в одну команду: сборка, база, демо-организация, сервер.
#
#   ./docker/up.sh            поднять (повторный запуск ничего не стирает)
#   ./docker/up.sh --reset    стереть ВСЁ (базу, ключи, журнал) и создать заново
#
# Демо-организация создаётся только при первом запуске. Она пишет корневой ЗАКРЫТЫЙ
# ключ в том alerting_demo-keys — для стенда и показа, не для боевого сервера
# (docs/12-docker.md §5).
#
# За корпоративным TLS-прокси: ALERTING_BUILD_FLAGS="--secret id=ca,src=/path/ca.crt"
set -Eeuo pipefail

cd "$(dirname "$(readlink -f "$0")")/.."
env_file=docker/.env
compose=(docker compose --env-file "$env_file")

log() { printf '\n==> %s\n' "$*"; }
fail() { printf '\nОШИБКА: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || fail "docker не установлен"
docker compose version >/dev/null 2>&1 || fail "нет плагина docker compose"

if [[ "${1:-}" == "--reset" ]]; then
    log "стираю стенд: контейнеры, базу, ключи, журнал"
    "${compose[@]}" --profile init --profile cli down -v --remove-orphans
    [[ -f "$env_file" ]] && sed -i 's|^ALERTING_ROOT_PUBKEY=.*|ALERTING_ROOT_PUBKEY=|' "$env_file"
fi

[[ -f "$env_file" ]] || { cp docker/.env.example "$env_file"; log "создан $env_file"; }

log "собираю образ"
# shellcheck disable=SC2086  # флаги сборки намеренно разбиваются на слова
docker build -q ${ALERTING_BUILD_FLAGS:-} -t alerting:local . >/dev/null

root_key=$(sed -n 's/^ALERTING_ROOT_PUBKEY=//p' "$env_file")
have_db=$(docker volume ls -q --filter name='^alerting_pgdata$')

if [[ -n "$have_db" && -z "$root_key" ]]; then
    fail "база уже есть, а корневого ключа в $env_file нет. Впишите ключ этой
организации или начните с нуля: ./docker/up.sh --reset (сотрёт всё)"
fi

if [[ -z "$have_db" ]]; then
    log "первый запуск: создаю демо-организацию"
    out=$("${compose[@]}" --profile init run --rm -T org-init 2>&1) \
        || { printf '%s\n' "$out"; fail "org-init не прошёл"; }
    root_key=$(printf '%s\n' "$out" | grep -A1 'ORG ROOT PUBLIC KEY' | tail -1 | tr -d '[:space:]')
    [[ "$root_key" =~ ^[A-Za-z0-9_-]{43}$ ]] || { printf '%s\n' "$out"; fail "не нашёл корневой ключ в выводе org-init"; }
    sed -i "s|^ALERTING_ROOT_PUBKEY=.*|ALERTING_ROOT_PUBKEY=${root_key}|" "$env_file"
    printf '%s\n' "$out" | sed -n '/people:/,/^$/p' | grep -E '^\s+[a-z]-[0-9]+' || true
fi

log "запускаю"
"${compose[@]}" up -d --wait

port=$(sed -n 's/^ALERTING_PORT=//p' "$env_file"); port=${port:-8080}
ready=$(curl -fsS "http://127.0.0.1:${port}/v1/readyz" 2>/dev/null || true)
[[ "$ready" == *'"ready":true'* ]] || fail "сервер не готов: ${ready:-нет ответа}. Журнал: docker compose --env-file $env_file logs server"

cat <<EOF

ГОТОВО: http://127.0.0.1:${port}   (readyz: ready)
  корневой ключ организации : ${root_key}
  пароль ключей демо-людей  : demo

Учебный приказ:
  ./docker/cli.sh alerting-approver propose TEST.PING --drill --severity info \\
      --groups fire-wardens --text "проверка" --person p-001
  ./docker/cli.sh alerting-approver sign <id> --yes --person p-001
  ./docker/cli.sh alerting-executor sync --person x-102
  ./docker/cli.sh alerting-executor verify <id> --person x-102
  ./docker/cli.sh alerting-auditor verify --person a-001

Журнал сервера: docker compose --env-file $env_file logs -f server
EOF
