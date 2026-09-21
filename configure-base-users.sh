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
import tempfile
from datetime import datetime

import pymysql

from backend.main import db_config, db_cursor

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

# Allowlist explícita: sólo atributos funcionales/permisos.
# No se copian identificadores, credenciales secundarias, datos personales,
# hashes, IPs, contadores de login ni timestamps.
CLONE_FIELDS = [
    "delete_users", "delete_user_groups", "delete_lists", "delete_campaigns",
    "delete_ingroups", "delete_remote_agents", "load_leads", "campaign_detail",
    "ast_admin_access", "ast_delete_phones", "delete_scripts", "modify_leads",
    "hotkeys_active", "change_agent_campaign", "agent_choose_ingroups",
    "closer_campaigns", "scheduled_callbacks", "agentonly_callbacks",
    "agentcall_manual", "vicidial_recording", "vicidial_transfers",
    "delete_filters", "alter_agent_interface_options", "closer_default_blended",
    "delete_call_times", "modify_call_times", "modify_users", "modify_campaigns",
    "modify_lists", "modify_scripts", "modify_filters", "modify_ingroups",
    "modify_usergroups", "modify_remoteagents", "modify_servers", "view_reports",
    "vicidial_recording_override", "alter_custdata_override", "qc_enabled",
    "qc_user_level", "qc_pass", "qc_finish", "qc_commit", "add_timeclock_log",
    "modify_timeclock_log", "delete_timeclock_log", "alter_custphone_override",
    "vdc_agent_api_access", "modify_inbound_dids", "delete_inbound_dids",
    "alert_enabled", "download_lists", "agent_shift_enforcement_override",
    "manager_shift_enforcement_override", "shift_override_flag", "export_reports",
    "delete_from_dnc", "allow_alerts", "agent_choose_territories",
    "agent_call_log_view_override", "callcard_admin", "agent_choose_blended",
    "realtime_block_user_info", "custom_fields_modify", "force_change_password",
    "agent_lead_search_override", "modify_shifts", "modify_phones",
    "modify_carriers", "modify_labels", "modify_statuses", "modify_voicemail",
    "modify_audiostore", "modify_moh", "modify_tts", "preset_contact_search",
    "modify_contacts", "modify_same_user_level", "admin_hide_lead_data",
    "admin_hide_phone_data", "agentcall_email", "modify_email_accounts",
    "alter_admin_interface_options", "max_inbound_calls",
    "modify_custom_dialplans", "wrapup_seconds_override", "modify_languages",
    "selected_language", "user_choose_language", "ignore_group_on_search",
    "api_list_restrict", "api_allowed_functions", "lead_filter_id",
    "admin_cf_show_hidden", "agentcall_chat", "user_hide_realtime",
    "access_recordings", "modify_colors", "user_new_lead_limit", "api_only_user",
    "modify_auto_reports", "modify_ip_lists", "ignore_ip_list",
    "ready_max_logout", "export_gdpr_leads", "pause_code_approval",
    "max_hopper_calls", "max_hopper_calls_hour", "mute_recordings",
    "hide_call_log_info", "next_dial_my_callbacks", "user_admin_redirect_url",
    "max_inbound_filter_enabled", "max_inbound_filter_statuses",
    "max_inbound_filter_ingroups", "max_inbound_filter_min_sec",
    "status_group_id", "two_factor_override", "manual_dial_filter",
    "download_invalid_files", "user_group_two", "modify_dial_prefix",
    "inbound_credits", "hci_enabled", "manual_dial_lead_id",
]

EXCLUDED_FIELDS = {
    "user_id", "user", "pass", "full_name", "user_level", "user_group", "active",
    "phone_login", "phone_pass", "email", "user_code", "territory",
    "custom_one", "custom_two", "custom_three", "custom_four", "custom_five",
    "voicemail_id", "failed_login_count", "last_login_date", "last_ip",
    "pass_hash", "user_nickname", "mobile_number", "user_location",
    "failed_login_attempts_today", "failed_login_count_today",
    "failed_last_ip_today", "failed_last_type_today", "modify_stamp",
}

def base_user(group):
    prefix = "CC-CORTIZO-"
    suffix = group[len(prefix):] if group.startswith(prefix) else group
    suffix = re.sub(r"[^A-Za-z0-9]+", "_", suffix).strip("_").upper()
    candidate = "BASE_" + suffix
    if len(candidate) > 20:
        candidate = candidate[:20]
    return candidate

with db_cursor() as cursor:
    cursor.execute("SHOW COLUMNS FROM vicidial_users")
    schema_fields = set(row["Field"] for row in cursor.fetchall())

missing_clone_fields = [field for field in CLONE_FIELDS if field not in schema_fields]
if missing_clone_fields:
    print("[ERROR] El esquema cambió; faltan campos esperados:")
    for field in missing_clone_fields:
        print("  %s" % field)
    sys.exit(3)

unexpected_sensitive = sorted(set(CLONE_FIELDS).intersection(EXCLUDED_FIELDS))
if unexpected_sensitive:
    print("[ERROR] Campos sensibles en CLONE_FIELDS: %s"
          % ", ".join(unexpected_sensitive))
    sys.exit(4)

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

blocked = [row for row in plan if row[2] == "NO_SOURCE"]
if blocked:
    print("")
    print("[ERROR] Hay %d grupo(s) sin fuente válida; --apply queda bloqueado."
          % len(blocked))
    sys.exit(6)

print("")
print("Campos funcionales a clonar por usuario: %d" % len(CLONE_FIELDS))
print("Campos sensibles/personales excluidos: %d" % len(EXCLUDED_FIELDS))

if not apply_changes:
    print("")
    print("[DRY-RUN] No se escribió nada.")
    print("Revisa el plan y después ejecuta:")
    print("  ./configure-base-users.sh --apply")
    sys.exit(0)

created = 0
templates = {}

cfg = db_config()
cfg["autocommit"] = False
connection = pymysql.connect(**cfg)

try:
    cursor = connection.cursor()

    for group, username, action, source_user in plan:
        if action == "NO_SOURCE":
            raise RuntimeError(
                "%s no tiene agente fuente nivel 1 activo" % group
            )

        if action == "EXISTS":
            templates[group] = username
            continue

        # Revalidación dentro de la misma transacción.
        cursor.execute(
            "SELECT user FROM vicidial_users WHERE user=%s LIMIT 1",
            (username,),
        )
        if cursor.fetchone():
            raise RuntimeError(
                "%s apareció después del dry-run; se aborta para no sobrescribir"
                % username
            )

        select_fields = ", ".join("`%s`" % field for field in CLONE_FIELDS)
        cursor.execute(
            """
            SELECT %s
              FROM vicidial_users
             WHERE user=%%s
               AND user_group=%%s
               AND active='Y'
               AND user_level=1
             LIMIT 1
            """ % select_fields,
            (source_user, group),
        )
        source = cursor.fetchone()
        if not source:
            raise RuntimeError(
                "La fuente %s ya no es válida para %s" % (source_user, group)
            )

        insert_columns = [
            "user", "pass", "full_name", "user_level", "user_group", "active"
        ] + CLONE_FIELDS
        values = [
            username,
            defaults[group],
            "Usuario Base %s" % group,
            1,
            group,
            "N",
        ] + [source[field] for field in CLONE_FIELDS]

        columns_sql = ", ".join("`%s`" % field for field in insert_columns)
        placeholders = ", ".join(["%s"] * len(insert_columns))

        cursor.execute(
            "INSERT INTO vicidial_users (%s) VALUES (%s)"
            % (columns_sql, placeholders),
            values,
        )

        templates[group] = username
        created += 1
        print("[OK] Clonado %s <- %s (%s)"
              % (username, source_user, group))

    connection.commit()

except Exception as exc:
    connection.rollback()
    print("")
    print("[ROLLBACK] No se conservaron inserts de este lote.")
    print("[ERROR] %s" % exc)
    sys.exit(10)

finally:
    try:
        cursor.close()
    except Exception:
        pass
    connection.close()

# Sólo después del COMMIT exitoso actualizamos el mapa de plantillas.
existing_templates = {}
if os.path.exists(templates_path):
    try:
        with open(templates_path, "r") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            existing_templates = dict(data)

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = templates_path + ".bak_" + stamp
        with open(backup, "w") as fh:
            json.dump(existing_templates, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.chmod(backup, 0o640)
        print("[OK] Backup templates: %s" % backup)
    except Exception as exc:
        print("[WARN] No fue posible respaldar mapa anterior: %s" % exc)

existing_templates.update(templates)

directory = os.path.dirname(templates_path) or "."
fd, tmp_path = tempfile.mkstemp(prefix=".group_templates.", dir=directory)
try:
    with os.fdopen(fd, "w") as fh:
        json.dump(existing_templates, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.chmod(tmp_path, 0o640)
    os.replace(tmp_path, templates_path)
except Exception:
    try:
        os.unlink(tmp_path)
    except OSError:
        pass
    raise

print("")
print("[OK] COMMIT completado.")
print("[OK] Usuarios base creados: %d" % created)
print("[OK] Plantillas configuradas para este lote: %d" % len(templates))
print("[OK] Datos personales y credenciales secundarias excluidos.")
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
