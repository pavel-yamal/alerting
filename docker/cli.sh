#!/usr/bin/env bash
# CLI ЛПР, исполнителя и аудитора внутри стенда, без длинных флагов:
#
#   ./docker/cli.sh alerting-approver status <id> --person p-001
#
# Подставляет --server, --home по --person и демо-пароль, если их не указали.
set -Eeuo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."

[[ $# -ge 1 ]] || { echo "usage: $0 <alerting-approver|alerting-executor|alerting-auditor> ..." >&2; exit 2; }

args=("$@")
person=""
for ((i = 0; i < ${#args[@]}; i++)); do
    [[ "${args[i]}" == "--person" ]] && person="${args[i + 1]:-}"
done
extra=()
[[ " $* " == *" --server "* ]] || extra+=(--server http://server:8080)
[[ " $* " == *" --passphrase "* ]] || extra+=(--passphrase demo)
[[ -n "$person" && " $* " != *" --home "* ]] && extra+=(--home "/var/lib/alerting/clients/${person}")

exec docker compose --env-file docker/.env --profile cli run --rm -T cli "${args[@]}" "${extra[@]}"
