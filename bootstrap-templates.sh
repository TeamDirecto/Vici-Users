#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/vici-users"
CFG_DIR="/etc/vici-users"
CFG_FILE="${CFG_DIR}/group_templates.json"
EXAMPLE="${APP_DIR}/config/group_templates.example.json"

[ "$(id -u)" -eq 0 ] || { echo "[ERROR] Ejecuta como root" >&2; exit 1; }
[ -f "$EXAMPLE" ] || { echo "[ERROR] No existe $EXAMPLE" >&2; exit 1; }

mkdir -p "$CFG_DIR"
chmod 0750 "$CFG_DIR"

if [ ! -f "$CFG_FILE" ]; then
  install -m 0640 "$EXAMPLE" "$CFG_FILE"
  echo "[OK] Creado $CFG_FILE"
else
  echo "[OK] Ya existe $CFG_FILE; no se sobrescribió"
fi

/opt/vici-users/.venv/bin/python -m json.tool "$CFG_FILE" >/dev/null
echo "[OK] JSON válido"

echo
echo "Configura un único usuario base por grupo en:"
echo "  $CFG_FILE"
echo
echo 'Formato:'
echo '{'
echo '  "GRUPO_A": "USUARIO_BASE_A",'
echo '  "GRUPO_B": "USUARIO_BASE_B"'
echo '}'
echo
echo "Después de guardar:"
echo "  systemctl restart vici-users"
echo "  curl -s http://127.0.0.1:8094/api/health | /opt/vici-users/.venv/bin/python -m json.tool"
