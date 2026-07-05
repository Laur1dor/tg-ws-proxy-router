#!/usr/bin/env bash
# Установка TG WS/SOCKS5 Proxy на Linux (LXC / VPS) без Docker: venv + systemd.
#
#   tar xzf tgws.tar.gz && cd tgws
#   sudo bash deploy/install.sh
#
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "==> Установка из $APP_DIR"

if [ "$(id -u)" -ne 0 ]; then
  echo "Запусти под root (sudo)." >&2
  exit 1
fi

# --- зависимости ---
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -qq
  apt-get install -y --no-install-recommends python3 python3-venv python3-pip ca-certificates
elif command -v apk >/dev/null 2>&1; then
  apk add --no-cache python3 py3-pip
fi

# --- venv + зависимости питона ---
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --upgrade pip -q
"$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt" -q

# --- конфиг ---
if [ ! -f "$APP_DIR/config.yml" ]; then
  cp "$APP_DIR/config.example.yml" "$APP_DIR/config.yml"
  echo "==> Создан config.yml из примера"
  # Первичная настройка: вкл фрагментацию DPI (для РФ) + зафиксировать секреты.
  ( cd "$APP_DIR" && "$APP_DIR/.venv/bin/python" -c \
    "from proxy import menu; from proxy.config import proxy_config as p; \
menu.load('config.yml'); p.tls_fragment=True; menu.save('config.yml')" ) \
    && echo "==> tls_fragment=on, секреты зафиксированы" || true
else
  echo "==> config.yml уже есть — сохраняю как есть (только фиксирую секреты)"
  ( cd "$APP_DIR" && "$APP_DIR/.venv/bin/python" -c \
    "from proxy import menu; menu.load('config.yml'); menu.save('config.yml')" ) \
    || true
fi

# --- лаунчер панели в PATH ---
chmod +x "$APP_DIR/tgws.sh" "$APP_DIR/deploy/install.sh" 2>/dev/null || true
ln -sf "$APP_DIR/tgws.sh" /usr/local/bin/tgws || true

# --- systemd unit ---
sed "s#__APP_DIR__#${APP_DIR}#g" "$APP_DIR/deploy/tgws.service" \
    > /etc/systemd/system/tgws.service
systemctl daemon-reload
systemctl enable tgws >/dev/null 2>&1 || true
systemctl restart tgws

echo
echo "==> Готово."
echo "   Панель :  tgws            (или  cd $APP_DIR && ./tgws.sh)"
echo "   Логи   :  journalctl -u tgws -f"
echo "   Статус :  systemctl status tgws"
echo
echo "Дальше: запусти 'tgws' и в Расширенных (7) включи фрагментацию (6)"
echo "для РФ, проверь порты SOCKS5/MTProto и забери ссылки (пункт 1)."
