#!/usr/bin/env bash
# Полное удаление TG WS/SOCKS5 Proxy (systemd-установка).
#   sudo bash deploy/uninstall.sh            # удалить службу, файлы оставить
#   sudo bash deploy/uninstall.sh --purge    # удалить службу И каталог проекта
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "Запусти под root (sudo)." >&2
  exit 1
fi

echo "==> Останавливаю и отключаю службу tgws"
systemctl stop tgws 2>/dev/null || true
systemctl disable tgws 2>/dev/null || true
rm -f /etc/systemd/system/tgws.service
systemctl daemon-reload 2>/dev/null || true
rm -f /usr/local/bin/tgws

echo "==> Служба удалена."

if [ "${1:-}" = "--purge" ]; then
  echo "==> Удаляю каталог $APP_DIR"
  cd /
  rm -rf "$APP_DIR"
  echo "==> Готово, удалено полностью."
else
  echo "Файлы оставлены в $APP_DIR (конфиг с секретами тоже)."
  echo "Полностью удалить:  rm -rf $APP_DIR"
fi
