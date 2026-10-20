#!/usr/bin/env bash
# Перевести организацию на новый корневой ключ хранителей.
#
#   ./docker/rotate-root.sh ответ-acme-202610201930.json
#
# Файл ответа хранители подписали на компьютере без сети (окно хранителей, заявка
# с переносом). Это единственный шаг, который нельзя сделать из панели: он меняет,
# чему доверяет сервер, и поэтому доступен только администратору сервера.
#
# Что делает:
#   1. показывает отпечаток нового ключа и просит ВВЕСТИ его с карточки хранителей;
#   2. останавливает сервер и клиентов, записывает справочник и политику нового
#      корня (сервер сам проверяет подпись, отпечаток и версии), пишет в аудит;
#   3. меняет ALERTING_ROOT_PUBKEY в docker/.env и закреплённый ключ в домах стенда;
#   4. удаляет демо-корневой ключ и демо-ключ отзыва с сервера;
#   5. запускает всё обратно.
set -Eeuo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."

answer=${1:-}
[[ -n "$answer" && -f "$answer" ]] || { echo "usage: $0 <файл ответа хранителей>" >&2; exit 2; }
answer=$(readlink -f "$answer")
env_file=docker/.env
compose=(docker compose --env-file "$env_file")
mount=(-v "$answer:/in/answer.json:ro")

info=$("${compose[@]}" --profile cli run --rm -T "${mount[@]}" --entrypoint python cli -c '
import json
from alerting import custody
a = json.load(open("/in/answer.json"))
print(custody.fingerprint(a["root_public_key"]))
print(a["root_public_key"])
print("migration" if a.get("migration") else "plain")
' </dev/null)
fingerprint=$(sed -n 1p <<<"$info")
root=$(sed -n 2p <<<"$info")
kind=$(sed -n 3p <<<"$info")
[[ "$kind" == migration ]] || { echo "Это не перенос — опубликуйте ответ в панели (Справочник и ключи)." >&2; exit 2; }

echo
echo "Новый корневой ключ организации, отпечаток:"
echo
echo "    $fingerprint"
echo
echo "Сверьте с карточкой хранителей. Если не совпадает — остановитесь."
read -r -p "Введите отпечаток с карточки: " typed
norm() { tr -d '[:space:]' <<<"$1" | tr '[:upper:]' '[:lower:]'; }
if [[ "$(norm "$typed")" != "$(norm "$fingerprint")" ]]; then
    echo "Отпечаток не совпадает. Ничего не изменено." >&2
    exit 2
fi

echo "==> останавливаю сервер и клиентов"
"${compose[@]}" stop panel mobile server >/dev/null

echo "==> записываю справочник и политику нового корня"
if ! "${compose[@]}" run --rm -T --no-deps "${mount[@]}" server \
        import-root /in/answer.json --fingerprint "$typed" </dev/null; then
    echo "Импорт не прошёл — ничего не изменено. Запускаю обратно на прежнем ключе." >&2
    "${compose[@]}" up -d --wait >/dev/null
    exit 1
fi

echo "==> меняю ALERTING_ROOT_PUBKEY и закреплённый ключ стенда"
sed -i "s|^ALERTING_ROOT_PUBKEY=.*|ALERTING_ROOT_PUBKEY=${root}|" "$env_file"
"${compose[@]}" --profile cli run --rm -T -e NEW_ROOT="$root" \
    -v alerting_demo-keys:/var/lib/alerting/demo-keys --entrypoint python cli -c '
import json, os, pathlib, shutil
root = os.environ["NEW_ROOT"]
for pin in pathlib.Path("/var/lib/alerting/clients").glob("*/pin.json"):
    data = json.loads(pin.read_text())
    data["root_public_key"] = root
    pin.write_text(json.dumps(data, indent=2))
keys = pathlib.Path("/var/lib/alerting/demo-keys")
(keys / "root-key.SECRET").unlink(missing_ok=True)
shutil.rmtree(keys / "revoker", ignore_errors=True)
print("демо-корневой ключ и демо-ключ отзыва удалены с сервера")
' </dev/null

echo "==> запускаю"
"${compose[@]}" up -d --wait >/dev/null
echo
echo "Готово: организация на новом корневом ключе ($fingerprint)."
echo "Дальше люди и ключи меняются только через панель (Справочник и ключи) и хранителей."
echo "Если в справочнике остался ключ отзыва стенда — уберите его заявкой («Украден: убрать»)."
