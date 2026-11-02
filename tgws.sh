#!/usr/bin/env bash
# Лаунчер панели управления.
#   ./tgws.sh   или (после install.sh) одним словом:  tgws
set -e
# Резолвим реальный каталог скрипта, даже если вызван через симлинк в PATH.
SCRIPT="$(readlink -f "$0" 2>/dev/null || echo "$0")"
cd "$(dirname "$SCRIPT")"
# Предпочитаем venv (там стоит PyYAML), иначе системный python.
if [ -x "./.venv/bin/python" ]; then
  PY="./.venv/bin/python"
else
  PY="$(command -v python3 || command -v python)"
fi
if [ "${1:-}" = web ]; then
  shift
  exec "$PY" -m proxy.webui "$@"
fi
exec "$PY" -m proxy.menu "$@"
