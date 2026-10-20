#!/usr/bin/env bash
# Стенд: зарегистрировать человека (ключ устройства + контакт) или отозвать его ключ.
#
#   ./docker/person.sh add x-104 "Новиков П. С." fire-wardens      # исполнитель
#   ROLE=duty_officer SITE=HQ ./docker/person.sh add p-004 "Орлова Е. В."
#   ROLE=director PUBLIC_KEY=<с экрана регистрации панели> ./docker/person.sh add p-010 "Орлова Е. В."
#   ./docker/person.sh retire x-104                 # уволился: прежние подписи в силе
#   ./docker/person.sh revoke x-104 "утерян телефон" # ключом отзыва смены, за секунды
#   ./docker/person.sh show
#
# В боевом контуре это три места (docs/02-trust-and-approval.md §4): ключ создаётся на
# устройстве человека и не покидает его, справочник подписывают хранители корневого
# ключа на машине без сети, публикует дежурный. На стенде корневой ключ лежит в томе
# alerting_demo-keys, а «устройство» — каталог в томе clients, поэтому всё здесь.
set -Eeuo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."

usage() {
    sed -n '4,8p' "$0" | sed 's/^# \{0,1\}//' >&2
    exit 2
}
[[ $# -ge 1 ]] || usage
action=$1
shift

role=${ROLE:-executor}
site=${SITE:-}
pass=${PASSPHRASE:-demo}
operator=${OPERATOR:-p-001}
keys=/var/lib/alerting/demo-keys
clients=/var/lib/alerting/clients
as_operator="--server http://server:8080 --person ${operator} --home ${clients}/${operator} --passphrase demo"

# После переноса на ключ хранителей (rotate-root.sh) корневого ключа на сервере нет —
# и так должно быть. Тогда всё, кроме просмотра, делается в панели.
if [[ "$action" != show ]] && ! docker run --rm --entrypoint test \
        -v alerting_demo-keys:/k alerting:local -f /k/root-key.SECRET 2>/dev/null; then
    echo "Корневого ключа на сервере нет (организация на ключе хранителей)." >&2
    echo "Добавление и отзыв — в панели: «Справочник и ключи» → заявка хранителям / «Отозвать сейчас»." >&2
    exit 2
fi

case "$action" in
add)
    [[ $# -ge 2 ]] || usage
    person=$1 name=$2
    shift 2
    groups="$*"
    script="
      set -e
      org=\$(python -c 'import json; print(json.load(open(\"${clients}/${operator}/pin.json\"))[\"org_id\"])')
      root=\$(python -c 'import json; print(json.load(open(\"${clients}/${operator}/pin.json\"))[\"root_public_key\"])')
      if [ -n \"\$PUBLIC_KEY\" ]; then
        # Ключ создан на устройстве человека (экран регистрации панели) и его не покидает.
        alerting-org contact set ${as_operator} --for '${person}' --name \"\$NAME\" \
            --site '${site}' --role '${role}' --groups ${groups}
        public=\"\$PUBLIC_KEY\"
      else
        alerting-org contact set ${as_operator} --for '${person}' --name \"\$NAME\" \
            --site '${site}' --role '${role}' --groups ${groups} --wake-key-out /tmp/wake.hex
        alerting-executor enroll --person '${person}' --home '${clients}/${person}' \
            --passphrase \"\$PASS\" --org \"\$org\" --root-key \"\$root\" --role '${role}' \
            --wake-key \"\$(cat /tmp/wake.hex)\" | tee /tmp/enroll.txt
        public=\$(sed -n 's/^ *public key : //p' /tmp/enroll.txt)
      fi
      alerting-org fetch --kind directory --out /tmp/current.json ${as_operator}
      alerting-org directory add --from /tmp/current.json --root-key ${keys}/root-key.SECRET \
          --out /tmp/next.json --person '${person}' --name \"\$NAME\" --role '${role}' \
          --public-key \"\$public\"
      alerting-org publish --file /tmp/next.json ${as_operator}
    "
    ;;
retire)
    [[ $# -ge 1 ]] || usage
    person=$1
    script="
      set -e
      alerting-org fetch --kind directory --out /tmp/current.json ${as_operator}
      alerting-org directory retire --from /tmp/current.json \
          --root-key ${keys}/root-key.SECRET --out /tmp/next.json --person '${person}'
      alerting-org publish --file /tmp/next.json ${as_operator}
      alerting-org contact remove ${as_operator} --for '${person}'
    "
    ;;
revoke)
    # Быстрый путь: ключ отзыва дежурной смены, без корневого ключа. При первом вызове
    # ключ отзыва создаётся и вносится в справочник корневым ключом — один раз.
    [[ $# -ge 2 ]] || { echo "укажите причину отзыва" >&2; exit 2; }
    person=$1
    reason=$2
    script="
      set -e
      if [ ! -f ${keys}/revoker/keys/revoker.json ]; then
        echo '==> первый отзыв: создаю ключ отзыва и вношу его в справочник (корневой ключ)'
        alerting-org revoker-keygen --home ${keys}/revoker --passphrase demo | tee /tmp/rk.txt
        public=\$(sed -n 's/^ *public key : //p' /tmp/rk.txt)
        alerting-org fetch --kind directory --out /tmp/current.json ${as_operator}
        alerting-org directory revoker --add \"\$public\" --label 'дежурная смена (стенд)' \
            --from /tmp/current.json --root-key ${keys}/root-key.SECRET --out /tmp/next.json
        alerting-org publish --file /tmp/next.json ${as_operator}
        echo '==> отзыв ключом дежурной смены'
      fi
      alerting-org revoke-now ${as_operator} --for '${person}' --reason \"\$REASON\" \
          --revoker-home ${keys}/revoker --revoker-passphrase demo
      alerting-org contact remove ${as_operator} --for '${person}'
    "
    ;;
show)
    script="
      set -e
      alerting-org fetch --kind directory --out /tmp/current.json ${as_operator} >/dev/null
      alerting-org directory show --file /tmp/current.json
    "
    ;;
*) usage ;;
esac

docker compose --env-file docker/.env --profile cli run --rm -T \
    -e NAME="${name:-}" -e PASS="$pass" -e REASON="${reason:-}" -e PUBLIC_KEY="${PUBLIC_KEY:-}" \
    -v alerting_demo-keys:${keys} \
    --entrypoint sh cli -c "$script"
