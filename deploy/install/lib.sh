# Общее для установочных скриптов. Подключается через `source`, сам не запускается.
#
# Здесь всего две идеи, и обе про то, чтобы установка не расходилась с инвентарём.

set -Eeuo pipefail

log()  { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
warn() { log "ВНИМАНИЕ: $*"; }
fail() { log "УСТАНОВКА ПРЕРВАНА: $*"; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INVENTORY="${INVENTORY:-${REPO_ROOT}/deploy/inventory.env}"
INVENTORY_EXAMPLE="${REPO_ROOT}/deploy/inventory.example.env"

load_inventory() {
    [ -r "$INVENTORY" ] || fail "нет инвентаря ${INVENTORY}. \
Скопируйте deploy/inventory.example.env и заполните адреса."
    # shellcheck disable=SC1090
    set -a; . "$INVENTORY"; set +a
    : "${ALERTING_CONTOUR:?ALERTING_CONTOUR не задан в инвентаре (staging или production)}"
}

# Подстановка значений инвентаря в шаблон конфигурации.
#
# Механизм: примерные значения из inventory.example.env И ЕСТЬ плейсхолдеры. Для
# каждой переменной, заданной в обоих файлах, примерное значение заменяется на
# настоящее. Отсюда полезное свойство: шаблоны остаются валидными файлами, которые
# можно проверить как есть — `nft --check` на deploy/nftables/*.nft проходит до
# всякой установки. Шаблон с `@PLACEHOLDER@` внутри так проверить нельзя, а
# непроверяемый firewall — это firewall, который узнают в бою.
#
# Заменяются только значения, похожие на адрес, подсеть или имя хоста. Номера портов
# и версия PostgreSQL сюда не попадают намеренно: подстановка «16» по всему файлу
# испортила бы /usr/lib/postgresql/16/bin, а «5432» — половину комментариев. Там, где
# они нужны, скрипты подставляют их сами, явной строкой.
render() {
    local src="$1" dst="$2" name example actual count=0
    [ -r "$src" ] || fail "нет шаблона ${src}"
    local tmp; tmp="$(mktemp)"
    cp "$src" "$tmp"

    while IFS='=' read -r name example; do
        # `[A-Z0-9_]`, с цифрами. Первая версия была `[A-Z_]+` и молча пропускала
        # ALERTING_APP1_ADDR и ALERTING_APP2_ADDR — то есть ровно адреса двух узлов
        # приложения, самые нужные в nginx. Поймала это assert_rendered, а не глаз.
        case "$name" in ALERTING_*) ;; *) continue ;; esac
        actual="${!name-}"
        [ -n "$actual" ] || continue
        [ "$actual" != "$example" ] || continue
        # адрес, подсеть или имя хоста — и ничего короче
        case "$example" in
            *[0-9].[0-9]*|*.*.*) [ "${#example}" -ge 5 ] || continue ;;
            *) continue ;;
        esac
        sed -i "s|\\b${example}\\b|${actual}|g" "$tmp"
        count=$((count + 1))
    done < <(grep -E '^ALERTING_[A-Z0-9_]+=' "$INVENTORY_EXAMPLE")

    install -m "${3:-0644}" "$tmp" "$dst"
    rm -f "$tmp"
    log "  ${dst} (подстановок: ${count})"
}

# Шаблон, в котором остались примерные адреса, — это конфигурация чужого контура.
# Молча поставить её хуже, чем не поставить: firewall будет пускать не тех, а nginx
# ходить не туда, и оба будут выглядеть настроенными.
assert_rendered() {
    local file="$1" configured leftovers
    # Разрешено ровно то, что стоит в инвентаре, — список берётся из него, а не из
    # захардкоженного перечня: перечень отстал бы от инвентаря в первый же раз, когда
    # в него добавят адрес, и проверка начала бы пропускать именно новое.
    configured="$(grep -E '^ALERTING_[A-Z0-9_]+=' "$INVENTORY" | cut -d= -f2- \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)"
    leftovers="$(grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$file" | sort -u \
        | grep -vxF "$configured" || true)"
    # 127.0.0.1 и 0.0.0.0 — не адреса контура, они значат «эта машина» и «любой».
    leftovers="$(printf '%s\n' "$leftovers" | grep -vE '^(127\.0\.0\.1|0\.0\.0\.0)$' || true)"
    [ -z "$leftovers" ] \
        || fail "в ${file} остались адреса, которых нет в инвентаре: ${leftovers//$'\n'/, }. \
Это конфигурация чужого контура: firewall будет пускать не тех, а nginx ходить не туда, \
и оба будут выглядеть настроенными."
}

require_root() { [ "$(id -u)" -eq 0 ] || fail "нужны права root"; }

# Идемпотентность: повторный запуск установщика — нормальный рабочий случай, а не
# аварийный. Обновление версии, добавление узла, починка после неудачи — всё это
# запуск того же скрипта ещё раз.
ensure_user() {
    id alerting >/dev/null 2>&1 && return 0
    log "создаю пользователя alerting"
    useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/alerting \
        --no-create-home alerting
}

ensure_dirs() {
    install -d -o root -g alerting -m 0750 /etc/alerting
    install -d -o root -g root    -m 0700 /etc/alerting/credentials
    install -d -o alerting -g alerting -m 0750 /var/lib/alerting
    install -d -o alerting -g alerting -m 0750 /var/lib/alerting/spool
    install -d -o alerting -g alerting -m 0750 /var/lib/alerting/heads
    install -d -o alerting -g alerting -m 0750 /var/backups/alerting
}

# Секрет пишется атомарно и сразу с правами: файл, который на мгновение был доступен
# всем, был доступен всем.
write_secret() {
    local path="$1" content="$2" tmp
    tmp="$(mktemp)"; chmod 0400 "$tmp"
    printf '%s' "$content" > "$tmp"
    mv "$tmp" "$path"
    chown root:root "$path"
}

# Часы — не удобство. Окно рукопожатия устройства 60 с, допуск перекоса приказа
# ±120 с, и потеря синхронизации это молчаливый полный отказ: валидные клиенты
# начинают получать отказ, а узел выглядит здоровым. Юнит не стартует без
# `chronyc waitsync`, поэтому без chrony узел просто не поднимется.
ensure_chrony() {
    command -v chronyc >/dev/null 2>&1 && systemctl is-active --quiet chrony 2>/dev/null \
        && { log "chrony уже работает"; return 0; }
    log "ставлю chrony"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq chrony >/dev/null
    systemctl enable --now chrony
}

install_nft() {
    local src="$1" name; name="$(basename "$src")"
    install -d -m 0755 /etc/nftables.d
    render "$src" "/etc/nftables.d/${name}" 0644
    assert_rendered "/etc/nftables.d/${name}"
    nft --check -f "/etc/nftables.d/${name}" \
        || fail "правила ${name} не проходят проверку синтаксиса"
    # Подключить из nftables.conf, если ещё не подключено.
    grep -q 'include "/etc/nftables.d/\*.nft"' /etc/nftables.conf 2>/dev/null \
        || echo 'include "/etc/nftables.d/*.nft"' >> /etc/nftables.conf
    log "правила ${name} установлены и проверены"
    log "  применить: systemctl enable --now nftables && nft -f /etc/nftables.conf"
}
