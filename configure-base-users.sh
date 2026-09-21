#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="/opt/vici-users"
CFG_DIR="/etc/vici-users"
TEMPLATES_FILE="${CFG_DIR}/group_templates.json"
GROUPS_FILE="${APP_DIR}/config/managed_groups.json"
DEFAULTS_FILE="${CFG_DIR}/group_defaults.json"
PYTHON_BIN="${APP_DIR}/.venv/bin/python"
APPLY=0

if [ "${1:-}" = "--apply" ]; then
  APPLY=1
elif [ -n "${1:-}" ]; then
  echo "Uso: $0 [--apply]" >&2
  exit 1
fi

[ "$(id -u)" -eq 0 ] || { echo "[ERROR] Ejecuta como root" >&2; exit 1; }
[ -x "$PYTHON_BIN" ] || { echo "[ERROR] No existe $PYTHON_BIN" >&2; exit 1; }
[ -f "$GROUPS_FILE" ] || { echo "[ERROR] No existe $GROUPS_FILE" >&2; exit 1; }
[ -f "$DEFAULTS_FILE" ] || { echo "[ERROR] No existe $DEFAULTS_FILE" >&2; exit 1; }

cd "$APP_DIR"
mkdir -p "$CFG_DIR"
chmod 0750 "$CFG_DIR"

"$PYTHON_BIN" - "$GROUPS_FILE" "$DEFAULTS_FILE" "$TEMPLATES_FILE" "$APPLY" <<'PY'
import json
import os
import re
import sys

from backend.main import db_cursor

groups_path, defaults_path, templates_path, apply_raw = sys.argv[1:5]
apply_changes = apply_raw == "1"

with open(groups_path, "r") as fh:
    groups = [str(x).strip() for x in json.load(fh) if str(x).strip()]

with open(defaults_path, "r") as fh:
    defaults = json.load(fh)

missing_defaults = [g for g in groups if not defaults.get(g)]
if missing_defaults:
    print("[ERROR] Faltan passwords default:")
    for group in missing_defaults:
        print("  %s" % group)
    sys.exit(2)

def base_user(group):
    prefix = "CC-CORTIZO-"
    suffix = group[len(prefix):] if group.startswith(prefix) else group
    suffix = re.sub(r"[^A-Za-z0-9]+", "_", suffix).strip("_").upper()
    candidate = "BASE_" + suffix
    if len(candidate) > 20:
        candidate = candidate[:20]
    return candidate

plan = []
with db_cursor() as cursor:
    for group in groups:
        username = base_user(group)

        cursor.execute(
            "SELECT user, user_group, user_level, active, full_name "
            "FROM vicidial_users WHERE user=%s LIMIT 1",
            (username,),
        )
        existing = cursor.fetchone()

        cursor.execute(
            """
            SELECT user, full_name, user_level
              FROM vicidial_users
             WHERE user_group=%s
               AND active='Y'
               AND user_level=1
             ORDER BY user
             LIMIT 1
            """,
            (group,),
        )
        source = cursor.fetchone()

        if existing:
            if existing["user_group"] != group:
                print("[ERROR] %s ya existe pero pertenece a %s, no a %s"
                      % (username, existing["user_group"], group))
                sys.exit(3)
            plan.append((group, username, "EXISTS", existing.get("full_name") or ""))
            continue

        if not source:
            plan.append((group, username, "NO_SOURCE", ""))
            continue

        plan.append((group, username, "CREATE", source["user"]))

print("")
print("PLAN DE USUARIOS BASE")
print("======================")
for group, username, action, source in plan:
    if action == "CREATE":
        print("[CREATE] %-24s -> %-20s desde %s" % (group, username, source))
    elif action == "EXISTS":
        print("[OK]     %-24s -> %-20s ya existe" % (group, username))
    else:
        print("[WARN]   %-24s -> %-20s sin agente nivel 1 activo" % (group, username))

if not apply_changes:
    print("")
    print("[DRY-RUN] No se escribió nada.")
    print("Revisa el plan y después ejecuta:")
    print("  ./configure-base-users.sh --apply")
    sys.exit(0)

created = 0
skipped = 0
templates = {}

with db_cursor() as cursor:
    for group, username, action, source in plan:
        if action == "NO_SOURCE":
            print("[WARN] %s omitido: no hay fuente nivel 1 activa" % group)
            skipped += 1
            continue

        if action == "EXISTS":
            templates[group] = username
            continue

        password = defaults[group]

        # Se crea una plantilla técnica mínima. No se clonan credenciales,
        # phone_login, email ni otros identificadores del agente fuente.
        cursor.execute(
            """
            INSERT INTO vicidial_users
                (user, pass, full_name, user_level, user_group, active)
            VALUES
                (%s, %s, %s, 1, %s, 'N')
            """,
            (
                username,
                password,
                "Usuario Base %s" % group,
                group,
            ),
        )
        templates[group] = username
        created += 1
        print("[OK] Creado %s para %s" % (username, group))

# Conserva mapeos ajenos sólo si ya existían, pero sobrescribe los administrados.
existing_templates = {}
if os.path.exists(templates_path):
    try:
        with open(templates_path, "r") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            existing_templates = dict(data)
    except Exception:
        pass

existing_templates.update(templates)
with open(templates_path, "w") as fh:
    json.dump(existing_templates, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.chmod(templates_path, 0o640)

print("")
print("[OK] Usuarios base creados: %d" % created)
print("[OK] Plantillas configuradas: %d" % len(templates))
print("[WARN] Grupos omitidos: %d" % skipped)
PY

if [ "$APPLY" -eq 1 ]; then
  chown root:root "$TEMPLATES_FILE"
  chmod 0640 "$TEMPLATES_FILE"

  echo
  echo "Reinicia la API:"
  echo "  systemctl restart vici-users"
  echo
  echo "Valida:"
  echo "  curl -s http://127.0.0.1:8094/api/health | $PYTHON_BIN -m json.tool"
fi
