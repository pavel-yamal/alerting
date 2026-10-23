#!/usr/bin/env bash
# Собрать комплект для компьютера хранителей: всё нужное для установки без сети.
#
#   ./scripts/custodian-kit.sh                     # для такой же ОС, как эта машина
#   ./scripts/custodian-kit.sh win_amd64 3.12      # для Windows, Python 3.12
#   ./scripts/custodian-kit.sh manylinux2014_x86_64 3.11
#
# Результат — каталог custodian-kit/ : перенесите его на носитель. На компьютере
# хранителей (Python 3.11+):
#
#   python -m pip install --no-index --find-links custodian-kit alerting
#   alerting-custodian --vault <носитель>/root-vault.json
#
# и откройте в его браузере http://127.0.0.1:7090
set -Eeuo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."

platform=${1:-}
python_version=${2:-}
out=custodian-kit
rm -rf "$out"
mkdir -p "$out"

python3 -m pip wheel --no-deps --wheel-dir "$out" . >/dev/null
if [[ -z "$platform" ]]; then
    python3 -m pip wheel --wheel-dir "$out" . >/dev/null
else
    deps=$(python3 - <<'PY'
import tomllib
print(" ".join(tomllib.load(open("pyproject.toml", "rb"))["project"]["dependencies"]))
PY
)
    # shellcheck disable=SC2086  # список зависимостей намеренно разбивается
    python3 -m pip download --only-binary=:all: --platform "$platform" \
        ${python_version:+--python-version "$python_version"} --dest "$out" $deps >/dev/null
fi
cp docs/13-custodians.md "$out/ИНСТРУКЦИЯ.md"
echo "Комплект: $out/ ($(ls "$out" | wc -l) файлов). Перенесите на носитель."
