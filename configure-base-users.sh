#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/vici-users"
CFG_DIR="/etc/vici-users"
CFG_FILE="${CFG_DIR}/group_templates.json"
PYTHON_BIN="${APP_DIR}/.venv/bin/python"

[ "$(id -u)" -eq 0 ] || { echo "[ERROR] Ejecuta como root" >&2; exit 1; }
[ -x "$PYTHON_BIN" ] || { echo "[ERROR] No existe $PYTHON_BIN" >&2; exit 1; }
cd "$APP_DIR"

mkdir -p "$CFG_DIR"
chmod 0750 "$CFG_DIR"

if [ -f "$CFG_FILE" ]; then
  TS="$(date +%Y%m%d_%H%M%S)"
  cp -a "$CFG_FILE" "${CFG_FILE}.bak_${TS}"
  echo "[OK] Backup: ${CFG_FILE}.bak_${TS}"
fi

"$PYTHON_BIN" - "$CFG_FILE" <<'PY'
import json
import os
import sys

from backend.main import db_cursor

path = sys.argv[1]
groups = [
    "CC-CORTIZO-4PV",
    "CC-CORTIZO-BANCO-AZT",
    "CC-CORTIZO-BANORTE",
    "CC-CORTIZO-BBVA",
    "CC-CORTIZO-GMF",
    "CC-CORTIZO-LABORATOR",
]

existing = {}
if os.path.exists(path):
    try:
        with open(path, "r") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            existing = {str(k): str(v) for k, v in data.items() if v}
    except Exception:
        pass

result = dict(existing)

for group in groups:
    print("\n=== %s ===" % group)
    with db_cursor() as cursor:
        cursor.execute(
            """
            SELECT user, full_name, user_level, active
              FROM vicidial_users
             WHERE user_group=%s
               AND active='Y'
               AND user_level=1
             ORDER BY user
             LIMIT 20
            """,
            (group,),
        )
        rows = cursor.fetchall()

    if not rows:
        print("[WARN] No hay usuarios activos nivel 1 en este grupo.")
        continue

    current = existing.get(group)
    for idx, row in enumerate(rows, start=1):
        marker = " *actual*" if row["user"] == current else ""
        print("%2d) %-20s %s%s" % (idx, row["user"], row.get("full_name") or "", marker))

    default_idx = None
    if current:
        for idx, row in enumerate(rows, start=1):
            if row["user"] == current:
                default_idx = idx
                break
    if default_idx is None:
        default_idx = 1

    raw = input("Selecciona usuario base [%d]: " % default_idx).strip()
    if not raw:
        choice = default_idx
    else:
        try:
            choice = int(raw)
        except ValueError:
            print("[WARN] Selección inválida; se conserva/usa el default.")
            choice = default_idx

    if choice < 1 or choice > len(rows):
        print("[WARN] Selección fuera de rango; se conserva/usa el default.")
        choice = default_idx

    selected = rows[choice - 1]["user"]
    result[group] = selected
    print("[OK] %s -> %s" % (group, selected))

with open(path, "w") as fh:
    json.dump(result, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.chmod(path, 0o640)

print("\n[OK] Archivo actualizado: %s" % path)
print("[OK] Grupos con usuario base: %d" % len(result))
PY

chown root:root "$CFG_FILE"
chmod 0640 "$CFG_FILE"

echo
echo "Después reinicia:"
echo "  systemctl restart vici-users"
echo "  curl -s http://127.0.0.1:8094/api/groups | /opt/vici-users/.venv/bin/python -m json.tool"
