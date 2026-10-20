#!/usr/bin/env bash
# Общая часть для любой роли: пользователь, каталоги, часы, firewall.
#
#   ./common.sh <app|db|proxy>
#
# Запускается первым на каждой из пяти машин. Идемпотентен.
set -Eeuo pipefail
. "$(dirname "$(readlink -f "$0")")/lib.sh"

role="${1:?usage: common.sh <app|db|proxy>}"
require_root
load_inventory

log "=== общая подготовка: роль ${role} ==="

ensure_user
# Пользователь нужен и на узле базы, и на прокси: под ним ходит бэкап, и им же
# владеют каталоги. Одинаковый uid по машинам не нужен — файлы между ними не ездят.

case "$role" in
    app)
        ensure_dirs
        install_nft "${REPO_ROOT}/deploy/nftables/alerting-app.nft"
        ;;
    db)
        # Узлу базы не нужны ни спул, ни головы: их пишет сервер, а он здесь не
        # живёт. Нужен /var/backups/alerting — сюда ложится ночной дамп.
        install -d -o root -g alerting -m 0750 /etc/alerting
        install -d -o root -g root    -m 0700 /etc/alerting/credentials
        install -d -o alerting -g alerting -m 0750 /var/backups/alerting
        install_nft "${REPO_ROOT}/deploy/nftables/alerting-db.nft"
        ;;
    proxy)
        install_nft "${REPO_ROOT}/deploy/nftables/alerting-proxy.nft"
        ;;
    *)
        fail "неизвестная роль '${role}': app, db или proxy"
        ;;
esac

ensure_chrony

log "=== готово: ${role} ==="
log "Firewall установлен, но НЕ применён: применение обрывает текущие соединения,"
log "включая ваш ssh, если ADMIN_NET указан неверно. Проверьте адрес и примените"
log "вручную: systemctl enable --now nftables && nft -f /etc/nftables.conf"
