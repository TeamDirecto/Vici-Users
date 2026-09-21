#!/usr/bin/env bash
set -Eeuo pipefail

CFG_DIR="/etc/vici-users"
CFG_FILE="${CFG_DIR}/group_defaults.json"
GROUPS_FILE="/opt/vici-users/config/managed_groups.json"
PYTHON_BIN="/opt/vici-users/.venv/bin/python"

[ "$(id -u)" -eq 0 ] || { echo "[ERROR] Ejecuta como root" >&2; exit 1; }
[ -x "$PYTHON_BIN" ] || { echo "[ERROR] No existe $PYTHON_BIN" >&2; exit 1; }
[ -f "$GROUPS_FILE" ] || { echo "[ERROR] No existe $GROUPS_FILE" >&2; exit 1; }

mkdir -p "$CFG_DIR"
chmod 0750 "$CFG_DIR"

if [ -f "$CFG_FILE" ]; then
  TS="$(date +%Y%m%d_%H%M%S)"
  cp -a "$CFG_FILE" "${CFG_FILE}.bak_${TS}"
  echo "[OK] Backup: ${CFG_FILE}.bak_${TS}"
fi

"$PYTHON_BIN" - "$CFG_FILE" "$GROUPS_FILE" <<'PY'
import getpass
import json
import os
import sys

path = sys.argv[1]
groups_path = sys.argv[2]
with open(groups_path, "r") as fh:
    groups = json.load(fh)
groups = [str(g).strip() for g in groups if str(g).strip()]

existing = {}
if os.path.exists(path):
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            existing = {str(k): str(v) for k, v in data.items() if v}
    except Exception:
        pass

print("Configura password default por User Group.")
print("La captura no se muestra en pantalla y no se guarda en GitHub.")
print("Deja vacío para conservar el valor actual, si existe.\n")

result = dict(existing)
for group in groups:
    current = group in existing
    prompt = "%s%s: " % (group, " [ya configurado]" if current else "")
    value = getpass.getpass(prompt)
    if value:
        result[group] = value
    elif not current:
        print("  [WARN] %s queda sin password default" % group)

with open(path, "w") as fh:
    json.dump(result, fh, indent=2, sort_keys=True)
    fh.write("\n")

os.chmod(path, 0o600)
print("\n[OK] Archivo actualizado: %s" % path)
print("[OK] Grupos con password default: %d" % len(result))
PY

chown root:root "$CFG_FILE"
chmod 0600 "$CFG_FILE"

echo
echo "Valida sin mostrar secretos:"
echo "  /opt/vici-users/.venv/bin/python - <<'PY'"
echo "import json"
echo "p='/etc/vici-users/group_defaults.json'"
echo "d=json.load(open(p))"
echo "print('grupos configurados:', sorted(d.keys()))"
echo "PY"
echo
echo "Después reinicia:"
echo "  systemctl restart vici-users"
echo "  curl -s http://127.0.0.1:8094/api/health | /opt/vici-users/.venv/bin/python -m json.tool"
