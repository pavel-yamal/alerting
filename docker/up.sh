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
build_log=$(mktemp)
# shellcheck disable=SC2086  # флаги сборки намеренно разбиваются на слова
if ! docker build --progress=plain ${ALERTING_BUILD_FLAGS:-} -t alerting:local . >"$build_log" 2>&1; then
    # Без этого видно только «exit code: 1», а причина — в выводе pip выше.
    # Сводка docker в конце одинакова при любой причине; причина — в строках pip.
    # `|| true`: под set -e и pipefail пустой grep иначе молча завершил бы скрипт.
    cause=$(grep -E 'ERROR|[Ee]rror:|Could not|Retrying|Failed|denied|resolve host' "$build_log" \
        | grep -v 'failed to solve' | sed 's/^#[0-9]* [0-9.]* *//' | awk '!seen[$0]++' | head -15 || true)
    if [[ -n "$cause" ]]; then printf '%s\n' "$cause"; else tail -20 "$build_log"; fi
    rm -f "$build_log"
    fail "сборка не прошла (полный лог: docker build --progress=plain .)
Частые причины:
обрыв соединения с pypi.org (Connection reset) — зеркало или внутренний Nexus:
  ALERTING_BUILD_FLAGS=\"--build-arg PIP_INDEX_URL=https://<зеркало>/simple\" ./docker/up.sh
корпоративный прокси —
  ALERTING_BUILD_FLAGS=\"--build-arg HTTPS_PROXY=\$HTTPS_PROXY\" ./docker/up.sh
подмена TLS-сертификата прокси —
  ALERTING_BUILD_FLAGS=\"--secret id=ca,src=/path/ca.crt\" ./docker/up.sh"
fi
rm -f "$build_log"

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

port=$(sed -n 's/^ALERTING_PORT=//p' "$env_file"); port=${port:-7070}
panel_port=$(sed -n 's/^ALERTING_PANEL_PORT=//p' "$env_file"); panel_port=${panel_port:-7071}
ready=$(curl -fsS "http://127.0.0.1:${port}/v1/readyz" 2>/dev/null || true)
[[ "$ready" == *'"ready":true'* ]] || fail "сервер не готов: ${ready:-нет ответа}. Журнал: docker compose --env-file $env_file logs server"

cat <<EOF

ГОТОВО: http://127.0.0.1:${port}   (readyz: ready)
  корневой ключ организации : ${root_key}
  пароль ключей демо-людей  : demo

Панель дежурного: http://127.0.0.1:${panel_port}
  вход: p-003 (дежурный), p-001 (директор), p-002 (заместитель); пароль demo
  с другой машины: ssh -L ${panel_port}:127.0.0.1:${panel_port} <сервер>

Учебный приказ:
  ./docker/cli.sh alerting-approver propose TEST.PING --drill --severity info \\
      --groups fire-wardens --text "проверка" --person p-001
  ./docker/cli.sh alerting-approver sign <id> --yes --person p-001
  ./docker/cli.sh alerting-executor sync --person x-102
  ./docker/cli.sh alerting-executor verify <id> --person x-102
  ./docker/cli.sh alerting-auditor verify --person a-001

Журнал сервера: docker compose --env-file $env_file logs -f server
EOF
