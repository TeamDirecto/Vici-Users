#!/usr/bin/env bash
set -Eeuo pipefail

CFG_DIR="/etc/vici-users"
CFG_FILE="${CFG_DIR}/group_defaults.json"
GROUPS_FILE="/opt/vici-users/config/managed_groups.json"
PYTHON_BIN="/opt/vici-users/.venv/bin/python"
MODE="interactive"

if [ "${1:-}" = "--paste" ]; then
  MODE="paste"
elif [ -n "${1:-}" ]; then
  echo "Uso: $0 [--paste]" >&2
  exit 1
fi

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

if [ "$MODE" = "paste" ]; then
  TMP="$(mktemp)"
  trap 'rm -f "$TMP"' EXIT

  echo "Pega el compendio en formato:"
  echo "  USER-GROUP || password"
  echo
  echo "Al terminar presiona Ctrl-D."
  echo
  cat > "$TMP"

  "$PYTHON_BIN" - "$CFG_FILE" "$GROUPS_FILE" "$TMP" <<'PY'
import json
import os
import sys

cfg_path, groups_path, input_path = sys.argv[1:4]

with open(groups_path, "r") as fh:
    managed = [str(x).strip() for x in json.load(fh) if str(x).strip()]
managed_set = set(managed)

existing = {}
if os.path.exists(cfg_path):
    try:
        with open(cfg_path, "r") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            existing = {str(k).strip(): str(v) for k, v in data.items() if str(k).strip() and v}
    except Exception:
        pass

parsed = {}
unknown = []
invalid = []

with open(input_path, "r") as fh:
    for lineno, raw in enumerate(fh, start=1):
        line = raw.strip()
        if not line:
            continue
        if "||" not in line:
            invalid.append((lineno, line))
            continue
        group, password = [part.strip() for part in line.split("||", 1)]
        if not group or not password:
            invalid.append((lineno, line))
            continue
        if group not in managed_set:
            unknown.append(group)
            continue
        parsed[group] = password

if invalid:
    print("[ERROR] Líneas inválidas:")
    for lineno, line in invalid:
        print("  %d: %s" % (lineno, line))
    sys.exit(2)

if unknown:
    print("[ERROR] Grupos fuera de la allowlist:")
    for group in sorted(set(unknown)):
        print("  %s" % group)
    sys.exit(3)

missing = [group for group in managed if group not in parsed]
if missing:
    print("[ERROR] Faltan passwords para grupos administrados:")
    for group in missing:
        print("  %s" % group)
    sys.exit(4)

result = dict(existing)
for group in managed:
    result[group] = parsed[group]

with open(cfg_path, "w") as fh:
    json.dump(result, fh, indent=2, sort_keys=True)
    fh.write("\n")

os.chmod(cfg_path, 0o600)
print("[OK] Passwords cargados para %d grupos administrados." % len(managed))
print("[OK] No se imprimieron ni almacenaron en GitHub.")
PY

else
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
fi

chown root:root "$CFG_FILE"
chmod 0600 "$CFG_FILE"

echo
echo "Valida SIN mostrar secretos:"
echo "  $PYTHON_BIN - <<'PY'"
echo "import json"
echo "m=json.load(open('/opt/vici-users/config/managed_groups.json'))"
echo "d=json.load(open('/etc/vici-users/group_defaults.json'))"
echo "print('administrados:', len(m))"
echo "print('defaults configurados:', sum(1 for g in m if g in d and d[g]))"
echo "print('faltantes:', [g for g in m if not d.get(g)])"
echo "PY"
echo
echo "Después reinicia:"
echo "  systemctl restart vici-users"
