#!/usr/bin/env bash
# Стенд: подписать кодовую книгу демо-корневым ключом и опубликовать её.
#
#   cp config/scenarios.example.yaml config/scenarios.yaml   # и отредактировать
#   ./docker/policy.sh config/scenarios.yaml
#
# Делает то же, что в боевом контуре делают в два места (docs/02-trust-and-approval.md
# §5): `alerting-org sign-policy` на машине хранителей, `alerting-org publish` — с
# рабочего места. На стенде корневой ключ лежит в томе alerting_demo-keys, поэтому
# оба шага выполняются здесь. В боевом контуре так нельзя: корневой ключ не бывает на
# машине, подключённой к сети.
set -Eeuo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."

scenarios=${1:-config/scenarios.example.yaml}
policy=${POLICY_FILE:-config/policy.example.yaml}
[[ -f "$scenarios" ]] || { echo "нет файла $scenarios" >&2; exit 2; }
[[ -f "$policy" ]] || { echo "нет файла $policy" >&2; exit 2; }

compose=(docker compose --env-file docker/.env)
# Организация стенда — та, с которой его создал org-init. В примере политики
# записано "acme"; подписанная для другой организации политика сервер отвергает
# (org_mismatch).
org=$(sed -n 's/^ALERTING_ORG=//p' docker/.env | tr -d "\"'"); org=${org:-acme}
current=$("${compose[@]}" exec -T db psql -U postgres -d alerting -tAc \
    "SELECT COALESCE(MAX(version), 0) FROM bundles WHERE kind = 'policy'")
next=$((current + 1))
echo "==> организация ${org}; текущая версия политики: ${current}, публикую ${next}"

"${compose[@]}" --profile cli run --rm -T \
    -v "$PWD/$scenarios:/in/scenarios.yaml:ro" \
    -v "$PWD/$policy:/in/policy.yaml:ro" \
    -v alerting_demo-keys:/var/lib/alerting/demo-keys:ro \
    --entrypoint sh cli -c "
      set -e
      alerting-org sign-policy --policy /in/policy.yaml --scenarios /in/scenarios.yaml \
          --root-key /var/lib/alerting/demo-keys/root-key.SECRET --version ${next} --org ${org} \
          --out /tmp/policy.json
      alerting-org publish --file /tmp/policy.json --server http://server:8080 \
          --person p-001 --home /var/lib/alerting/clients/p-001 --passphrase demo
    "
echo "Панель покажет новый список при следующем обновлении экрана; страница исполнителя — после входа."
