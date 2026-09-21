import json
import os
import re
import socket
import sqlite3
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List, Optional, Set

import pymysql
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

APP_ROOT = Path(__file__).resolve().parent.parent
ASTGUI_CONF = Path(os.getenv("ASTGUI_CONF", "/etc/astguiclient.conf"))
EXPECTED_DB_HOST = os.getenv("VICI_DB_EXPECTED_HOST", "172.20.20.198")
CREATE_ENABLED = os.getenv("VICI_USERS_ENABLE_CREATE", "false").lower() in {"1", "true", "yes", "y"}
USERNAME_MAX_LENGTH = int(os.getenv("VICI_USERS_USERNAME_MAX_LENGTH", "20"))
GROUP_TEMPLATES_FILE = Path(
    os.getenv("VICI_USERS_GROUP_TEMPLATES_FILE", "/etc/vici-users/group_templates.json")
)
GROUP_DEFAULTS_FILE = Path(
    os.getenv("VICI_USERS_GROUP_DEFAULTS_FILE", "/etc/vici-users/group_defaults.json")
)
MANAGED_GROUPS_FILE = Path(
    os.getenv(
        "VICI_USERS_MANAGED_GROUPS_FILE",
        str(APP_ROOT / "config" / "managed_groups.json"),
    )
)
EXTENSION_RANGES_FILE = Path(
    os.getenv(
        "VICI_USERS_EXTENSION_RANGES_FILE",
        str(APP_ROOT / "config" / "extension_ranges.json"),
    )
)
INVENTORY_DB_FILE = Path(
    os.getenv(
        "VICI_USERS_INVENTORY_DB",
        "/var/lib/vici-users/extension_inventory.db",
    )
)
CLUSTER_NODES_FILE = Path(
    os.getenv(
        "VICI_USERS_CLUSTER_NODES_FILE",
        str(APP_ROOT / "config" / "cluster_nodes.json"),
    )
)
USER_CLONE_FIELDS = [
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

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "VICI_USERS_CORS_ORIGINS",
        "https://teamdirecto.github.io",
    ).split(",")
    if origin.strip()
]

app = FastAPI(title="Vici-Users API", version="0.14.0-write-plan-dry-run")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


def _read_astguiclient_conf():
    # type: () -> Dict[str, str]
    values = {}
    if not ASTGUI_CONF.exists():
        return values

    wanted = {
        "VARDB_server": "host",
        "VARDB_database": "database",
        "VARDB_user": "user",
        "VARDB_pass": "password",
        "VARDB_port": "port",
    }

    for raw in ASTGUI_CONF.read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=>" not in line:
            continue
        key, value = [part.strip() for part in line.split("=>", 1)]
        if key in wanted:
            values[wanted[key]] = value
    return values


def _load_json_mapping(path, label):
    if not path.exists():
        return {}
    try:
        with path.open("r") as fh:
            data = json.load(fh)
    except (ValueError, OSError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Configuración %s inválida: %s" % (label, exc),
        )

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=503,
            detail="%s debe contener un objeto JSON" % path.name,
        )
    return data


def load_group_templates():
    # type: () -> Dict[str, str]
    data = _load_json_mapping(GROUP_TEMPLATES_FILE, "de plantillas")
    clean = {}
    for group, user in data.items():
        group = str(group).strip()
        user = str(user).strip()
        if group and user:
            clean[group] = user
    return clean


def load_group_defaults():
    # type: () -> Dict[str, str]
    data = _load_json_mapping(GROUP_DEFAULTS_FILE, "de defaults")
    clean = {}
    for group, password in data.items():
        group = str(group).strip()
        password = str(password)
        if group and password:
            clean[group] = password
    return clean


def load_managed_groups():
    # type: () -> List[str]
    if not MANAGED_GROUPS_FILE.exists():
        return []
    try:
        with MANAGED_GROUPS_FILE.open("r") as fh:
            data = json.load(fh)
    except (ValueError, OSError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Configuración de grupos administrados inválida: %s" % exc,
        )
    if not isinstance(data, list):
        raise HTTPException(
            status_code=503,
            detail="%s debe contener una lista JSON" % MANAGED_GROUPS_FILE.name,
        )
    clean = []
    seen = set()
    for group in data:
        group = str(group).strip()
        if group and group not in seen:
            clean.append(group)
            seen.add(group)
    return clean


def load_extension_ranges():
    # type: () -> Dict[str, Dict[str, int]]
    data = _load_json_mapping(EXTENSION_RANGES_FILE, "de rangos de extensiones")
    clean = {}
    managed = set(load_managed_groups())

    for group, value in data.items():
        group = str(group).strip()
        if group not in managed:
            raise HTTPException(
                status_code=503,
                detail="Rango configurado para grupo no administrado: %s" % group,
            )
        if not isinstance(value, dict):
            raise HTTPException(
                status_code=503,
                detail="Rango inválido para %s" % group,
            )
        try:
            start = int(value["start"])
            end = int(value["end"])
        except (KeyError, TypeError, ValueError):
            raise HTTPException(
                status_code=503,
                detail="Rango inválido para %s: start/end requeridos" % group,
            )
        if start <= 0 or end < start:
            raise HTTPException(
                status_code=503,
                detail="Rango inválido para %s: %s-%s" % (group, start, end),
            )
        capacity = end - start + 1
        if capacity > 50:
            raise HTTPException(
                status_code=503,
                detail="Rango de %s excede el máximo de 50 extensiones" % group,
            )
        clean[group] = {"start": start, "end": end, "capacity": capacity}
    return clean


def load_cluster_nodes():
    data = _load_json_mapping(CLUSTER_NODES_FILE, "de topología del cluster")
    raw_nodes = data.get("nodes")
    if not isinstance(raw_nodes, list) or not raw_nodes:
        raise HTTPException(
            status_code=503,
            detail="cluster_nodes.json debe contener una lista nodes no vacía",
        )

    nodes = []
    seen = set()
    for item in raw_nodes:
        if not isinstance(item, dict):
            raise HTTPException(
                status_code=503,
                detail="Nodo inválido en cluster_nodes.json",
            )
        server_ip = str(item.get("server_ip") or "").strip()
        if not server_ip or server_ip in seen:
            raise HTTPException(
                status_code=503,
                detail="server_ip vacío o duplicado en cluster_nodes.json",
            )
        seen.add(server_ip)
        login_suffix = str(item.get("login_suffix") or "").strip()
        dialplan_prefix = str(item.get("dialplan_prefix") or "")
        if len(login_suffix) != 1:
            raise HTTPException(
                status_code=503,
                detail="login_suffix inválido para %s" % server_ip,
            )
        nodes.append({
            "server_ip": server_ip,
            "enabled": bool(item.get("enabled", True)),
            "login_suffix": login_suffix,
            "dialplan_prefix": dialplan_prefix,
            "note": str(item.get("note") or "").strip(),
        })

    if not any(node["enabled"] for node in nodes):
        raise HTTPException(
            status_code=503,
            detail="La topología no tiene nodos habilitados para provisión",
        )

    return {
        "cluster": str(data.get("cluster") or "EHECTO"),
        "identity_policy": str(data.get("identity_policy") or "canonical-v1"),
        "nodes": nodes,
    }


def canonical_phone_plan(user_group, extension):
    extension_range = require_provisioning_group(user_group)
    extension_text = str(extension).strip()
    if not extension_text.isdigit():
        raise HTTPException(status_code=400, detail="La extensión debe ser numérica")

    extension_number = int(extension_text)
    if extension_number < extension_range["start"] or extension_number > extension_range["end"]:
        raise HTTPException(
            status_code=409,
            detail="La extensión %s está fuera del bloque de %s" % (
                extension_text,
                user_group,
            ),
        )

    topology = load_cluster_nodes()
    nodes = []
    for node in topology["nodes"]:
        nodes.append({
            "server_ip": node["server_ip"],
            "enabled": node["enabled"],
            "login": extension_text + node["login_suffix"],
            "dialplan_number": node["dialplan_prefix"] + extension_text,
            "login_suffix": node["login_suffix"],
            "dialplan_prefix": node["dialplan_prefix"],
        })

    return {
        "user_group": user_group,
        "extension": extension_text,
        "identity_policy": topology.get("identity_policy", "canonical-v1"),
        "required_nodes": sum(1 for node in nodes if node["enabled"]),
        "nodes": nodes,
    }


def phone_provisioning_dry_run(user_group, extension):
    extension_range = require_provisioning_group(user_group)
    identity = canonical_phone_plan(user_group, extension)
    extension_text = identity["extension"]
    range_start = str(extension_range["start"])
    range_end = str(extension_range["end"])

    enabled_nodes = [node for node in identity["nodes"] if node["enabled"]]
    all_logins = [node["login"] for node in identity["nodes"]]
    all_dialplans = [node["dialplan_number"] for node in identity["nodes"]]

    with db_cursor() as cursor:
        cursor.execute(
            """
            SELECT extension, server_ip, user_group, active
              FROM phones
             WHERE extension=%s
             ORDER BY server_ip
            """,
            (extension_text,),
        )
        existing_extension_rows = cursor.fetchall()

        login_placeholders = ",".join(["%s"] * len(all_logins))
        cursor.execute(
            """
            SELECT extension, server_ip, login
              FROM phones
             WHERE login IN (%s)
             ORDER BY login, server_ip
            """ % login_placeholders,
            tuple(all_logins),
        )
        login_collisions = cursor.fetchall()

        dialplan_placeholders = ",".join(["%s"] * len(all_dialplans))
        cursor.execute(
            """
            SELECT extension, server_ip, dialplan_number
              FROM phones
             WHERE dialplan_number IN (%s)
             ORDER BY dialplan_number, server_ip
            """ % dialplan_placeholders,
            tuple(all_dialplans),
        )
        dialplan_collisions = cursor.fetchall()

        node_plans = []
        blockers = []
        warnings = []

        for node in identity["nodes"]:
            cursor.execute(
                """
                SELECT extension, server_ip, active, user_group, protocol,
                       template_id, ext_context, phone_context, is_webphone,
                       codecs_list, codecs_with_template,
                       LENGTH(conf_secret) AS conf_secret_len
                  FROM phones
                 WHERE user_group=%s
                   AND server_ip=%s
                   AND active='Y'
                   AND extension >= %s
                   AND extension <= %s
                 ORDER BY extension
                 LIMIT 1
                """,
                (
                    user_group,
                    node["server_ip"],
                    range_start,
                    range_end,
                ),
            )
            source = cursor.fetchone()

            template_ok = bool(
                source
                and source.get("template_id")
                and int(source.get("conf_secret_len") or 0) > 0
            )

            node_plan = {
                "server_ip": node["server_ip"],
                "enabled": node["enabled"],
                "required": node["enabled"],
                "target_login": node["login"],
                "target_dialplan_number": node["dialplan_number"],
                "template_found": source is not None,
                "template_ok": template_ok,
                "template_source_extension": (
                    str(source["extension"]) if source else None
                ),
                "template_summary": (
                    {
                        "protocol": source.get("protocol"),
                        "template_id": source.get("template_id"),
                        "ext_context": source.get("ext_context"),
                        "phone_context": source.get("phone_context"),
                        "is_webphone": source.get("is_webphone"),
                        "codecs_list": source.get("codecs_list"),
                        "codecs_with_template": source.get("codecs_with_template"),
                        "conf_secret_configured": int(source.get("conf_secret_len") or 0) > 0,
                    }
                    if source else None
                ),
            }
            node_plans.append(node_plan)

            if node["enabled"] and not template_ok:
                blockers.append(
                    "NODE_TEMPLATE_MISSING_OR_INVALID:%s" % node["server_ip"]
                )
            elif not node["enabled"] and not template_ok:
                warnings.append(
                    "DISABLED_NODE_TEMPLATE_MISSING_OR_INVALID:%s" % node["server_ip"]
                )

    if existing_extension_rows:
        blockers.append("TARGET_EXTENSION_ALREADY_EXISTS")

    enabled_logins = set(node["login"] for node in enabled_nodes)
    enabled_dialplans = set(node["dialplan_number"] for node in enabled_nodes)

    enabled_login_collisions = [
        row for row in login_collisions if str(row.get("login") or "") in enabled_logins
    ]
    enabled_dialplan_collisions = [
        row for row in dialplan_collisions
        if str(row.get("dialplan_number") or "") in enabled_dialplans
    ]

    if enabled_login_collisions:
        blockers.append("TARGET_LOGIN_COLLISION")
    if enabled_dialplan_collisions:
        blockers.append("TARGET_DIALPLAN_COLLISION")

    disabled_login_collisions = [
        row for row in login_collisions if str(row.get("login") or "") not in enabled_logins
    ]
    disabled_dialplan_collisions = [
        row for row in dialplan_collisions
        if str(row.get("dialplan_number") or "") not in enabled_dialplans
    ]
    if disabled_login_collisions:
        warnings.append("DISABLED_NODE_LOGIN_COLLISION")
    if disabled_dialplan_collisions:
        warnings.append("DISABLED_NODE_DIALPLAN_COLLISION")

    status = "READY" if not blockers else "BLOCKED"

    return {
        "mode": "DRY_RUN",
        "write_performed": False,
        "status": status,
        "user_group": user_group,
        "extension": extension_text,
        "identity_policy": identity["identity_policy"],
        "required_nodes": identity["required_nodes"],
        "storage_engine": "MyISAM",
        "rollback_strategy": "COMPENSATING_DELETE_UPDATE",
        "precheck": {
            "extension_unused": not bool(existing_extension_rows),
            "enabled_login_collisions": len(enabled_login_collisions),
            "enabled_dialplan_collisions": len(enabled_dialplan_collisions),
            "templates_ready": all(
                row["template_ok"] for row in node_plans if row["required"]
            ),
        },
        "blockers": blockers,
        "warnings": warnings,
        "nodes": node_plans,
    }


def provisioning_write_plan(user_group, username, full_name, extension):
    require_provisioning_group(user_group)
    username = str(username or "").strip().upper()
    full_name = str(full_name or "").strip()
    extension_text = str(extension or "").strip()

    blockers = []
    warnings = []

    if not username or len(username) > USERNAME_MAX_LENGTH:
        blockers.append("INVALID_USERNAME_LENGTH")
    elif not all(ch.isalnum() or ch == "_" for ch in username):
        blockers.append("INVALID_USERNAME_CHARACTERS")

    if not full_name:
        blockers.append("FULL_NAME_REQUIRED")

    phone_plan = phone_provisioning_dry_run(user_group, extension_text)
    blockers.extend(phone_plan.get("blockers", []))
    warnings.extend(phone_plan.get("warnings", []))

    templates = load_group_templates()
    template_user = templates.get(user_group)
    if not template_user:
        blockers.append("USER_TEMPLATE_NOT_CONFIGURED")

    default_password_configured = user_group in load_group_defaults()
    if not default_password_configured:
        blockers.append("DEFAULT_PASSWORD_NOT_CONFIGURED")

    identity = canonical_phone_plan(user_group, extension_text)
    enabled_identity = dict(
        (node["server_ip"], node)
        for node in identity["nodes"]
        if node["enabled"]
    )

    with db_cursor() as cursor:
        cursor.execute(
            "SELECT user, user_group, active FROM vicidial_users WHERE user=%s LIMIT 1",
            (username,),
        )
        existing_user = cursor.fetchone()
        if existing_user:
            blockers.append("TARGET_USER_ALREADY_EXISTS")

        source_user = None
        if template_user:
            cursor.execute(
                """
                SELECT user, user_group, user_level, active
                  FROM vicidial_users
                 WHERE user=%s
                   AND user_group=%s
                 LIMIT 1
                """,
                (template_user, user_group),
            )
            source_user = cursor.fetchone()
            if not source_user:
                blockers.append("USER_TEMPLATE_ROW_MISSING")

        cursor.execute("SHOW COLUMNS FROM vicidial_users")
        user_schema = set(row["Field"] for row in cursor.fetchall())
        missing_user_fields = [
            field for field in USER_CLONE_FIELDS if field not in user_schema
        ]
        if missing_user_fields:
            blockers.append("USER_SCHEMA_ALLOWLIST_MISMATCH")

        cursor.execute("SHOW COLUMNS FROM phones")
        phone_columns = [row["Field"] for row in cursor.fetchall()]

        phone_nodes = []
        phone_override_fields = {
            "extension",
            "dialplan_number",
            "voicemail_id",
            "server_ip",
            "login",
            "pass",
            "active",
            "user_group",
        }

        source_by_server = dict(
            (row["server_ip"], row)
            for row in phone_plan.get("nodes", [])
            if row.get("enabled")
        )

        for server_ip, target in enabled_identity.items():
            source_meta = source_by_server.get(server_ip) or {}
            source_extension = source_meta.get("template_source_extension")
            source_row = None

            if source_extension:
                cursor.execute(
                    """
                    SELECT *
                      FROM phones
                     WHERE extension=%s
                       AND server_ip=%s
                     LIMIT 1
                    """,
                    (source_extension, server_ip),
                )
                source_row = cursor.fetchone()

            if not source_row:
                blockers.append("PHONE_TEMPLATE_ROW_MISSING:%s" % server_ip)
                phone_nodes.append({
                    "server_ip": server_ip,
                    "status": "BLOCKED",
                    "source_extension": source_extension,
                    "target_extension": extension_text,
                })
                continue

            unmapped_references = []
            source_extension_text = str(source_extension)
            for field, value in source_row.items():
                if field in phone_override_fields or value is None:
                    continue
                value_text = str(value)
                if source_extension_text and source_extension_text in value_text:
                    unmapped_references.append(field)

            if unmapped_references:
                for field in unmapped_references:
                    blockers.append(
                        "UNMAPPED_PHONE_TEMPLATE_REFERENCE:%s:%s"
                        % (server_ip, field)
                    )

            override_values = {
                "extension": extension_text,
                "dialplan_number": target["dialplan_number"],
                "voicemail_id": extension_text,
                "server_ip": server_ip,
                "login": target["login"],
                "pass": extension_text,
                "active": "N",
                "user_group": user_group,
            }

            select_parts = []
            safe_parameters = []
            for field in phone_columns:
                if field in override_values:
                    select_parts.append("%s AS `%s`" % ("%s", field))
                    safe_parameters.append({
                        "field": field,
                        "value": override_values[field],
                    })
                else:
                    select_parts.append("`%s`" % field)

            columns_sql = ", ".join("`%s`" % field for field in phone_columns)
            select_sql = ", ".join(select_parts)
            insert_sql = (
                "INSERT INTO phones (%s) "
                "SELECT %s FROM phones "
                "WHERE extension=%%s AND server_ip=%%s LIMIT 1"
                % (columns_sql, select_sql)
            )

            safe_parameters.append({
                "field": "source_extension",
                "value": source_extension_text,
            })
            safe_parameters.append({
                "field": "source_server_ip",
                "value": server_ip,
            })

            phone_nodes.append({
                "server_ip": server_ip,
                "status": "READY" if not unmapped_references else "REVIEW",
                "source_extension": source_extension_text,
                "target_extension": extension_text,
                "changed_fields": [
                    {"field": "extension", "from": source_extension_text, "to": extension_text},
                    {"field": "dialplan_number", "from": str(source_row.get("dialplan_number") or ""), "to": target["dialplan_number"]},
                    {"field": "voicemail_id", "from": str(source_row.get("voicemail_id") or ""), "to": extension_text},
                    {"field": "server_ip", "from": str(source_row.get("server_ip") or ""), "to": server_ip},
                    {"field": "login", "from": str(source_row.get("login") or ""), "to": target["login"]},
                    {"field": "pass", "from": "<SOURCE_PHONE_PASS>", "to": "<TARGET_EXTENSION>"},
                    {"field": "active", "from": str(source_row.get("active") or ""), "to": "N"},
                    {"field": "user_group", "from": str(source_row.get("user_group") or ""), "to": user_group},
                ],
                "copied_fields_count": len(phone_columns) - len(phone_override_fields),
                "conf_secret_strategy": "COPY_FROM_NODE_TEMPLATE",
                "unmapped_source_extension_references": unmapped_references,
                "sql_template": insert_sql,
                "safe_parameters_in_order": safe_parameters,
            })

    user_columns = [
        "user", "pass", "full_name", "user_level", "user_group", "active"
    ] + list(USER_CLONE_FIELDS)
    user_columns_sql = ", ".join("`%s`" % field for field in user_columns)
    user_select_sql = ", ".join(
        ["%s", "%s", "%s", "%s", "%s", "%s"]
        + ["`%s`" % field for field in USER_CLONE_FIELDS]
    )
    user_insert_sql = (
        "INSERT INTO vicidial_users (%s) "
        "SELECT %s FROM vicidial_users "
        "WHERE user=%%s AND user_group=%%s LIMIT 1"
        % (user_columns_sql, user_select_sql)
    )

    unique_blockers = []
    seen_blockers = set()
    for blocker in blockers:
        if blocker not in seen_blockers:
            unique_blockers.append(blocker)
            seen_blockers.add(blocker)

    unique_warnings = []
    seen_warnings = set()
    for warning in warnings:
        if warning not in seen_warnings:
            unique_warnings.append(warning)
            seen_warnings.add(warning)

    status = "READY" if not unique_blockers else "BLOCKED"

    enabled_servers = [
        node["server_ip"]
        for node in phone_nodes
        if node.get("status") in {"READY", "REVIEW"}
    ]
    server_placeholders = ",".join(["%s"] * len(enabled_servers)) if enabled_servers else "%s"
    activate_phones_sql = (
        "UPDATE phones SET active='Y' "
        "WHERE extension=%s AND user_group=%s "
        "AND server_ip IN (%s)" % ("%s", "%s", server_placeholders)
    )
    rollback_phones_sql = (
        "DELETE FROM phones "
        "WHERE extension=%s AND user_group=%s "
        "AND server_ip IN (%s)" % ("%s", "%s", server_placeholders)
    )

    return {
        "mode": "DRY_RUN_WRITE_PLAN",
        "write_performed": False,
        "create_enabled": CREATE_ENABLED,
        "status": status,
        "user_group": user_group,
        "username": username,
        "full_name": full_name,
        "extension": extension_text,
        "storage_engines": {
            "phones": "MyISAM",
            "vicidial_users": "MyISAM",
        },
        "rollback_strategy": "COMPENSATING_DELETE_UPDATE",
        "user_plan": {
            "source_user": template_user,
            "target_user": username,
            "clone_fields_count": len(USER_CLONE_FIELDS),
            "identity_overrides": {
                "user": username,
                "pass": "<SERVER_SIDE_GROUP_PASSWORD>",
                "full_name": full_name,
                "user_level": 1,
                "user_group": user_group,
                "active": "N",
            },
            "sql_template": user_insert_sql,
            "safe_parameters_in_order": [
                username,
                "<SERVER_SIDE_GROUP_PASSWORD>",
                full_name,
                1,
                user_group,
                "N",
                template_user,
                user_group,
            ],
            "final_activation_sql": (
                "UPDATE vicidial_users SET active='Y' "
                "WHERE user=%s AND user_group=%s"
            ),
        },
        "phones_plan": phone_nodes,
        "operation_order": [
            "REVALIDATE_TARGET_USER_AND_EXTENSION",
            "RESERVE_EXTENSION_IN_LOCAL_INVENTORY",
            "INSERT_REQUIRED_PHONES_AS_ACTIVE_N",
            "VALIDATE_REQUIRED_PHONES",
            "INSERT_USER_AS_ACTIVE_N",
            "VALIDATE_USER",
            "ACTIVATE_REQUIRED_PHONES",
            "ACTIVATE_USER",
            "VALIDATE_FINAL_USER_AND_PHONES",
            "MARK_EXTENSION_IN_USE",
        ],
        "activation_sql": {
            "phones": activate_phones_sql,
            "user": (
                "UPDATE vicidial_users SET active='Y' "
                "WHERE user=%s AND user_group=%s"
            ),
        },
        "compensation_sql": {
            "phones": rollback_phones_sql,
            "user": (
                "DELETE FROM vicidial_users "
                "WHERE user=%s AND user_group=%s"
            ),
        },
        "blockers": unique_blockers,
        "warnings": unique_warnings,
    }


def extension_candidate_pool(user_group):
    extension_range = require_provisioning_group(user_group)
    topology = load_cluster_nodes()
    enabled_servers = set(
        node["server_ip"] for node in topology["nodes"] if node["enabled"]
    )
    extensions = [
        str(value)
        for value in range(extension_range["start"], extension_range["end"] + 1)
    ]
    placeholders = ",".join(["%s"] * len(extensions))

    with db_cursor() as cursor:
        cursor.execute(
            """
            SELECT extension, server_ip, active, user_group
              FROM phones
             WHERE extension IN (%s)
             ORDER BY extension, server_ip
            """ % placeholders,
            tuple(extensions),
        )
        phone_rows = cursor.fetchall()

    phones_by_extension = dict((extension, []) for extension in extensions)
    for row in phone_rows:
        extension = str(row.get("extension") or "")
        if extension in phones_by_extension:
            phones_by_extension[extension].append(row)

    local_inventory = load_local_inventory(user_group)
    free_candidates = []
    uncreated_candidates = []

    for extension in extensions:
        rows = phones_by_extension.get(extension, [])
        tracked = local_inventory.get(extension)

        if tracked:
            status = str(tracked.get("status") or "").upper()
            released_at = tracked.get("released_at")
            if status != "FREE" or not released_at or not rows:
                continue

            servers = set(
                str(row.get("server_ip") or "").strip()
                for row in rows
                if str(row.get("server_ip") or "").strip()
            )
            groups_aligned = all(
                str(row.get("user_group") or "").strip() == user_group
                for row in rows
            )
            if enabled_servers.issubset(servers) and groups_aligned:
                free_candidates.append({
                    "extension": extension,
                    "source": "FREE",
                    "action": "REUSE_EXISTING",
                    "released_at": str(released_at),
                })
            continue

        if not rows:
            uncreated_candidates.append({
                "extension": extension,
                "source": "UNCREATED",
                "action": "CREATE_PHONES",
                "released_at": None,
            })

    free_candidates.sort(
        key=lambda row: (row["released_at"], int(row["extension"]))
    )
    uncreated_candidates.sort(key=lambda row: int(row["extension"]))
    return free_candidates + uncreated_candidates


def preview_extension_allocations(user_group, requested):
    requested = int(requested)
    if requested <= 0:
        return {
            "requested": 0,
            "allocated": 0,
            "candidates_considered": 0,
            "allocations": [],
            "rejected": [],
        }

    candidates = extension_candidate_pool(user_group)
    topology = load_cluster_nodes()
    enabled_nodes = [node for node in topology["nodes"] if node["enabled"]]
    extension_range = require_provisioning_group(user_group)
    range_start = str(extension_range["start"])
    range_end = str(extension_range["end"])

    template_sources = {}
    with db_cursor() as cursor:
        for node in enabled_nodes:
            cursor.execute(
                """
                SELECT extension, server_ip, protocol, template_id,
                       ext_context, phone_context, is_webphone,
                       LENGTH(conf_secret) AS conf_secret_len
                  FROM phones
                 WHERE user_group=%s
                   AND server_ip=%s
                   AND active='Y'
                   AND extension >= %s
                   AND extension <= %s
                 ORDER BY extension
                 LIMIT 1
                """,
                (
                    user_group,
                    node["server_ip"],
                    range_start,
                    range_end,
                ),
            )
            source = cursor.fetchone()
            template_sources[node["server_ip"]] = source

        uncreated = [row for row in candidates if row["source"] == "UNCREATED"]
        target_logins = []
        target_dialplans = []
        plans = {}

        for candidate in uncreated:
            plan = canonical_phone_plan(user_group, candidate["extension"])
            plans[candidate["extension"]] = plan
            for node in plan["nodes"]:
                if node["enabled"]:
                    target_logins.append(node["login"])
                    target_dialplans.append(node["dialplan_number"])

        login_collisions = set()
        if target_logins:
            placeholders = ",".join(["%s"] * len(target_logins))
            cursor.execute(
                "SELECT login FROM phones WHERE login IN (%s)" % placeholders,
                tuple(target_logins),
            )
            login_collisions = set(
                str(row.get("login") or "") for row in cursor.fetchall()
            )

        dialplan_collisions = set()
        if target_dialplans:
            placeholders = ",".join(["%s"] * len(target_dialplans))
            cursor.execute(
                "SELECT dialplan_number FROM phones "
                "WHERE dialplan_number IN (%s)" % placeholders,
                tuple(target_dialplans),
            )
            dialplan_collisions = set(
                str(row.get("dialplan_number") or "") for row in cursor.fetchall()
            )

    templates_ready = all(
        source
        and source.get("template_id")
        and int(source.get("conf_secret_len") or 0) > 0
        for source in template_sources.values()
    )

    allocations = []
    rejected = []

    for candidate in candidates:
        if len(allocations) >= requested:
            break

        extension = candidate["extension"]
        if candidate["source"] == "FREE":
            allocations.append({
                "extension": extension,
                "source": "FREE",
                "action": "REUSE_EXISTING",
                "status": "READY",
                "released_at": candidate["released_at"],
            })
            continue

        plan = plans.get(extension)
        reasons = []

        if not templates_ready:
            reasons.append("NODE_TEMPLATE_MISSING_OR_INVALID")

        if plan:
            enabled_plan_nodes = [node for node in plan["nodes"] if node["enabled"]]
            if any(node["login"] in login_collisions for node in enabled_plan_nodes):
                reasons.append("TARGET_LOGIN_COLLISION")
            if any(
                node["dialplan_number"] in dialplan_collisions
                for node in enabled_plan_nodes
            ):
                reasons.append("TARGET_DIALPLAN_COLLISION")

        if reasons:
            rejected.append({
                "extension": extension,
                "source": "UNCREATED",
                "status": "BLOCKED",
                "reasons": reasons,
            })
            continue

        allocations.append({
            "extension": extension,
            "source": "UNCREATED",
            "action": "CREATE_PHONES",
            "status": "READY",
            "identity_policy": (
                plan["identity_policy"] if plan else topology["identity_policy"]
            ),
        })

    return {
        "requested": requested,
        "allocated": len(allocations),
        "candidates_considered": len(candidates),
        "templates_ready": templates_ready,
        "required_nodes": len(enabled_nodes),
        "allocations": allocations,
        "rejected": rejected,
    }


def require_managed_group(user_group):
    managed = set(load_managed_groups())
    if user_group not in managed:
        raise HTTPException(
            status_code=403,
            detail="El User Group %s no está autorizado para el flujo de clonación" % user_group,
        )


def require_provisioning_group(user_group):
    require_managed_group(user_group)
    ranges = load_extension_ranges()
    if user_group not in ranges:
        raise HTTPException(
            status_code=409,
            detail=(
                "El User Group %s está temporalmente fuera del flujo de alta "
                "porque no tiene bloque de extensiones configurado"
            ) % user_group,
        )
    return ranges[user_group]



def ensure_inventory_db():
    # type: () -> None
    try:
        INVENTORY_DB_FILE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        connection = sqlite3.connect(str(INVENTORY_DB_FILE), timeout=5)
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS extension_inventory (
                    extension TEXT PRIMARY KEY,
                    user_group TEXT NOT NULL,
                    status TEXT NOT NULL,
                    current_user TEXT,
                    previous_user TEXT,
                    reserved_at TEXT,
                    assigned_at TEXT,
                    released_at TEXT,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    note TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS extension_inventory_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    extension TEXT NOT NULL,
                    user_group TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    old_status TEXT,
                    new_status TEXT,
                    user_name TEXT,
                    detail TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_extension_inventory_group_status "
                "ON extension_inventory(user_group, status)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_extension_events_extension "
                "ON extension_inventory_events(extension, created_at)"
            )
            connection.commit()
        finally:
            connection.close()
        os.chmod(str(INVENTORY_DB_FILE), 0o600)
    except (OSError, sqlite3.Error) as exc:
        raise HTTPException(
            status_code=503,
            detail="No fue posible preparar el inventario local de extensiones: %s" % exc,
        )


def load_local_inventory(user_group):
    # type: (str) -> Dict[str, Dict[str, Optional[str]]]
    ensure_inventory_db()
    connection = None
    try:
        connection = sqlite3.connect(str(INVENTORY_DB_FILE), timeout=5)
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """
            SELECT extension, user_group, status, current_user, previous_user,
                   reserved_at, assigned_at, released_at, updated_at, note
              FROM extension_inventory
             WHERE user_group=?
            """,
            (user_group,),
        ).fetchall()
        return dict((str(row["extension"]), dict(row)) for row in rows)
    except sqlite3.Error as exc:
        raise HTTPException(
            status_code=503,
            detail="No fue posible consultar el inventario local de extensiones: %s" % exc,
        )
    finally:
        if connection:
            connection.close()


def extension_inventory_snapshot(user_group):
    extension_range = require_provisioning_group(user_group)
    topology = load_cluster_nodes()
    enabled_servers = set(
        node["server_ip"] for node in topology["nodes"] if node["enabled"]
    )
    known_servers = set(node["server_ip"] for node in topology["nodes"])
    start = extension_range["start"]
    end = extension_range["end"]
    extensions = [str(value) for value in range(start, end + 1)]
    placeholders = ",".join(["%s"] * len(extensions))

    with db_cursor() as cursor:
        cursor.execute(
            """
            SELECT extension, server_ip, active, user_group
              FROM phones
             WHERE extension IN (%s)
             ORDER BY extension, server_ip
            """ % placeholders,
            tuple(extensions),
        )
        phone_rows = cursor.fetchall()

    phones_by_extension = dict((extension, []) for extension in extensions)
    for row in phone_rows:
        extension = str(row.get("extension") or "")
        if extension in phones_by_extension:
            phones_by_extension[extension].append(row)

    local_inventory = load_local_inventory(user_group)
    positions = []
    counts = {
        "UNCREATED": 0,
        "LEGACY": 0,
        "FREE": 0,
        "RESERVED": 0,
        "IN_USE": 0,
        "ERROR": 0,
    }
    mismatches = 0
    incomplete = 0
    unexpected_server_rows = 0

    for extension in extensions:
        rows = phones_by_extension.get(extension, [])
        tracked = local_inventory.get(extension)
        if tracked:
            status = str(tracked.get("status") or "ERROR").upper()
            if status not in counts:
                status = "ERROR"
        elif rows:
            status = "LEGACY"
        else:
            status = "UNCREATED"

        counts[status] += 1

        row_groups = [
            str(row.get("user_group") or "").strip()
            for row in rows
        ]
        phone_groups = sorted(set(group for group in row_groups if group))
        servers = sorted(set(
            str(row.get("server_ip") or "").strip()
            for row in rows
            if str(row.get("server_ip") or "").strip()
        ))
        server_set = set(servers)
        enabled_present = server_set.intersection(enabled_servers)
        missing_enabled = sorted(enabled_servers.difference(server_set))
        unexpected_servers = sorted(server_set.difference(known_servers))
        unexpected_server_rows += len(unexpected_servers)

        if not rows:
            alignment = "N/A"
        elif all(group == user_group for group in row_groups):
            alignment = "ALIGNED"
        else:
            alignment = "MISMATCH"
            mismatches += 1

        if not rows:
            topology_status = "UNCREATED"
            topology_complete = False
        elif not missing_enabled:
            topology_status = "COMPLETE"
            topology_complete = True
        else:
            topology_status = "INCOMPLETE"
            topology_complete = False
            incomplete += 1

        positions.append({
            "extension": extension,
            "status": status,
            "managed_by_portal": tracked is not None,
            "server_count": len(servers),
            "enabled_server_count": len(enabled_present),
            "expected_enabled_server_count": len(enabled_servers),
            "servers": servers,
            "missing_enabled_servers": missing_enabled,
            "unexpected_servers": unexpected_servers,
            "topology_status": topology_status,
            "topology_complete": topology_complete,
            "active_rows": sum(
                1 for row in rows if str(row.get("active") or "").upper() == "Y"
            ),
            "phone_groups": phone_groups,
            "group_alignment": alignment,
            "current_user": tracked.get("current_user") if tracked else None,
            "previous_user": tracked.get("previous_user") if tracked else None,
            "released_at": tracked.get("released_at") if tracked else None,
            "updated_at": tracked.get("updated_at") if tracked else None,
        })

    free_candidates = [
        row["extension"] for row in positions
        if row["status"] == "FREE" and row["topology_complete"]
    ]
    uncreated_candidates = [
        row["extension"] for row in positions if row["status"] == "UNCREATED"
    ]
    next_candidate = None
    next_candidate_source = None
    if free_candidates:
        next_candidate = free_candidates[0]
        next_candidate_source = "FREE"
    elif uncreated_candidates:
        next_candidate = uncreated_candidates[0]
        next_candidate_source = "UNCREATED"

    return {
        "user_group": user_group,
        "extension_range": extension_range,
        "summary": {
            "capacity": len(extensions),
            "uncreated": counts["UNCREATED"],
            "legacy": counts["LEGACY"],
            "free": counts["FREE"],
            "reserved": counts["RESERVED"],
            "in_use": counts["IN_USE"],
            "error": counts["ERROR"],
            "group_mismatches": mismatches,
            "topology_incomplete": incomplete,
            "expected_enabled_nodes": len(enabled_servers),
            "disabled_nodes": len(topology["nodes"]) - len(enabled_servers),
            "unexpected_server_rows": unexpected_server_rows,
            "next_candidate": next_candidate,
            "next_candidate_source": next_candidate_source,
        },
    }

def db_config():
    conf = _read_astguiclient_conf()
    host = os.getenv("VICI_DB_HOST", conf.get("host", EXPECTED_DB_HOST))
    database = os.getenv("VICI_DB_NAME", conf.get("database", "asterisk"))
    user = os.getenv("VICI_DB_USER", conf.get("user", "cron"))
    password = os.getenv("VICI_DB_PASS", conf.get("password", ""))
    port = int(os.getenv("VICI_DB_PORT", conf.get("port", "3306") or "3306"))

    if EXPECTED_DB_HOST and host != EXPECTED_DB_HOST:
        raise HTTPException(
            status_code=503,
            detail="DB host rechazado por seguridad: %s. EHECTO espera vici222 (%s)." % (
                host,
                EXPECTED_DB_HOST,
            ),
        )

    return {
        "host": host,
        "database": database,
        "user": user,
        "password": password,
        "port": port,
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
        "connect_timeout": 4,
        "read_timeout": 8,
        "write_timeout": 8,
        "autocommit": True,
    }


@contextmanager
def db_cursor():
    connection = None
    try:
        connection = pymysql.connect(**db_config())
        with connection.cursor() as cursor:
            yield cursor
    except HTTPException:
        raise
    except pymysql.MySQLError as exc:
        raise HTTPException(
            status_code=503,
            detail="No fue posible consultar VICIdial DB en vici222: %s" % exc,
        )
    finally:
        if connection:
            connection.close()


def normalize_token(value):
    text = unicodedata.normalize("NFD", value or "")
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    text = text.replace("Ñ", "N").replace("ñ", "n")
    return re.sub(r"[^A-Za-z0-9]", "", text).upper()


def first_name(value):
    parts = (value or "").strip().split()
    return normalize_token(parts[0]) if parts else ""


def candidate_for(last_name, name, prefix_len):
    raw = "%s%s" % (last_name[:prefix_len], name)
    return raw[:USERNAME_MAX_LENGTH]


def get_group_template(user_group):
    templates = load_group_templates()
    template_user = templates.get(user_group)
    if not template_user:
        return None

    with db_cursor() as cursor:
        cursor.execute(
            """
            SELECT user, full_name, user_level, user_group, active,
                   hotkeys_active, agent_choose_ingroups, agent_choose_blended,
                   scheduled_callbacks, agentonly_callbacks
              FROM vicidial_users
             WHERE user=%s
               AND user_group=%s
             LIMIT 1
            """,
            (template_user, user_group),
        )
        return cursor.fetchone()


def resolve_agent_password(user_group, override_password=None):
    """Resuelve password sin exponerlo. Override gana; si no, usa default server-side."""
    if override_password:
        return override_password
    defaults = load_group_defaults()
    password = defaults.get(user_group)
    if not password:
        raise HTTPException(
            status_code=409,
            detail="El User Group %s no tiene password default configurado" % user_group,
        )
    return password


class PersonIn(BaseModel):
    first_names: str = Field(..., min_length=1, max_length=120)
    paternal: str = Field(..., min_length=1, max_length=80)
    maternal: str = Field("", max_length=80)


class PreviewRequest(BaseModel):
    user_group: str = Field(..., min_length=1, max_length=20)
    people: List[PersonIn] = Field(..., min_items=1, max_items=500)


class CreateRequest(PreviewRequest):
    usernames: List[str] = Field(..., min_items=1, max_items=500)
    agent_pass: Optional[str] = Field(None, min_length=1, max_length=100)


class WritePlanRequest(BaseModel):
    user_group: str = Field(..., min_length=1, max_length=20)
    username: str = Field(..., min_length=1, max_length=20)
    full_name: str = Field(..., min_length=1, max_length=50)
    extension: str = Field(..., min_length=1, max_length=20)


@app.get("/api/health")
def health():
    db_ok = False
    db_host = EXPECTED_DB_HOST
    row = {"db_node": None, "db_name": None}

    try:
        cfg = db_config()
        db_host = cfg["host"]
        with db_cursor() as cursor:
            cursor.execute("SELECT @@hostname AS db_node, DATABASE() AS db_name, 1 AS ok")
            row = cursor.fetchone() or row
            db_ok = row.get("ok") == 1
    except HTTPException:
        db_ok = False

    try:
        template_count = len(load_group_templates())
        templates_ok = True
    except HTTPException:
        template_count = 0
        templates_ok = False

    try:
        default_count = len(load_group_defaults())
        defaults_ok = True
    except HTTPException:
        default_count = 0
        defaults_ok = False

    try:
        managed_count = len(load_managed_groups())
        managed_ok = True
    except HTTPException:
        managed_count = 0
        managed_ok = False

    try:
        extension_ranges_count = len(load_extension_ranges())
        extension_ranges_ok = True
    except HTTPException:
        extension_ranges_count = 0
        extension_ranges_ok = False

    try:
        ensure_inventory_db()
        inventory_db_ok = True
    except HTTPException:
        inventory_db_ok = False

    try:
        topology = load_cluster_nodes()
        provisioning_nodes_count = sum(1 for node in topology["nodes"] if node["enabled"])
        disabled_nodes_count = sum(1 for node in topology["nodes"] if not node["enabled"])
        cluster_topology_ok = True
    except HTTPException:
        provisioning_nodes_count = 0
        disabled_nodes_count = 0
        cluster_topology_ok = False

    return {
        "status": "ok" if db_ok else "degraded",
        "app_node": socket.gethostname(),
        "target": "EHECTO",
        "db_role": "vici222 / DataBase Only",
        "db_host": db_host,
        "expected_db_host": EXPECTED_DB_HOST,
        "db_node": row.get("db_node"),
        "db_name": row.get("db_name"),
        "db_ok": db_ok,
        "create_enabled": CREATE_ENABLED,
        "username_max_length": USERNAME_MAX_LENGTH,
        "python_compat": "3.6+",
        "cors_origins": CORS_ORIGINS,
        "group_templates_file": str(GROUP_TEMPLATES_FILE),
        "group_templates_ok": templates_ok,
        "group_templates_count": template_count,
        "group_defaults_file": str(GROUP_DEFAULTS_FILE),
        "group_defaults_ok": defaults_ok,
        "group_defaults_count": default_count,
        "managed_groups_file": str(MANAGED_GROUPS_FILE),
        "managed_groups_ok": managed_ok,
        "managed_groups_count": managed_count,
        "extension_ranges_file": str(EXTENSION_RANGES_FILE),
        "extension_ranges_ok": extension_ranges_ok,
        "extension_ranges_count": extension_ranges_count,
        "inventory_db_file": str(INVENTORY_DB_FILE),
        "inventory_db_ok": inventory_db_ok,
        "cluster_nodes_file": str(CLUSTER_NODES_FILE),
        "cluster_topology_ok": cluster_topology_ok,
        "provisioning_nodes_count": provisioning_nodes_count,
        "disabled_nodes_count": disabled_nodes_count,
    }


@app.get("/api/groups")
def groups():
    templates = load_group_templates()
    defaults = load_group_defaults()
    ranges = load_extension_ranges()
    managed_groups = load_managed_groups()
    managed_set = set(managed_groups)

    with db_cursor() as cursor:
        cursor.execute(
            """
            SELECT user_group, group_name
              FROM vicidial_user_groups
             WHERE user_group IS NOT NULL
               AND user_group <> ''
             ORDER BY user_group
            """
        )
        rows = cursor.fetchall()

    rows = [row for row in rows if row["user_group"] in managed_set]
    order = dict((group, idx) for idx, group in enumerate(managed_groups))
    rows.sort(key=lambda row: order.get(row["user_group"], 999999))

    for row in rows:
        group = row["user_group"]
        row["template_configured"] = group in templates
        row["template_user"] = templates.get(group)
        row["default_password_configured"] = group in defaults
        row["provisioning_enabled"] = group in ranges
        row["extension_range"] = ranges.get(group)
    return {"groups": rows}


@app.get("/api/groups/{user_group}/template")
def group_template(user_group):
    require_managed_group(user_group)
    templates = load_group_templates()
    defaults = load_group_defaults()
    ranges = load_extension_ranges()
    configured_user = templates.get(user_group)
    if not configured_user:
        return {
            "user_group": user_group,
            "configured": False,
            "default_password_configured": user_group in defaults,
            "provisioning_enabled": user_group in ranges,
            "extension_range": ranges.get(user_group),
            "template": None,
        }

    template = get_group_template(user_group)
    if not template:
        raise HTTPException(
            status_code=409,
            detail=(
                "La plantilla configurada %s no existe, está inactiva o no pertenece al grupo %s"
                % (configured_user, user_group)
            ),
        )

    return {
        "user_group": user_group,
        "configured": True,
        "default_password_configured": user_group in defaults,
        "provisioning_enabled": user_group in ranges,
        "extension_range": ranges.get(user_group),
        "template": template,
    }


@app.get("/api/groups/{user_group}/users")
def group_users(user_group):
    require_managed_group(user_group)
    # Endpoint de diagnóstico/configuración. El front operativo no lo usa.
    with db_cursor() as cursor:
        cursor.execute(
            """
            SELECT user, full_name, user_level, user_group, active
              FROM vicidial_users
             WHERE user_group=%s
               AND active='Y'
             ORDER BY user
            """,
            (user_group,),
        )
        return {"user_group": user_group, "users": cursor.fetchall()}


@app.get("/api/users/{user}")
def user_detail(user):
    with db_cursor() as cursor:
        cursor.execute(
            """
            SELECT user, full_name, user_level, user_group, active,
                   hotkeys_active, agent_choose_ingroups, agent_choose_blended,
                   scheduled_callbacks, agentonly_callbacks
              FROM vicidial_users
             WHERE user=%s
             LIMIT 1
            """,
            (user,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        return row


@app.get("/api/groups/{user_group}/extension-range")
def group_extension_range(user_group):
    extension_range = require_provisioning_group(user_group)
    return {
        "user_group": user_group,
        "provisioning_enabled": True,
        "extension_range": extension_range,
    }


@app.get("/api/groups/{user_group}/extensions/inventory")
def group_extension_inventory(user_group):
    return extension_inventory_snapshot(user_group)


@app.get("/api/groups/{user_group}/extensions/{extension}/plan")
def group_extension_plan(user_group, extension):
    return canonical_phone_plan(user_group, extension)


@app.get("/api/groups/{user_group}/extensions/{extension}/provisioning-plan")
def group_extension_provisioning_plan(user_group, extension):
    return phone_provisioning_dry_run(user_group, extension)


@app.get("/api/extensions/audit")
def extension_audit():
    ranges = load_extension_ranges()
    managed_groups = load_managed_groups()
    order = dict((group, idx) for idx, group in enumerate(managed_groups))
    groups = []

    for user_group in sorted(ranges.keys(), key=lambda group: order.get(group, 999999)):
        snapshot = extension_inventory_snapshot(user_group)
        groups.append({
            "user_group": user_group,
            "extension_range": snapshot["extension_range"],
            "summary": snapshot["summary"],
        })

    return {
        "groups": groups,
        "totals": {
            "groups": len(groups),
            "capacity": sum(row["summary"]["capacity"] for row in groups),
            "uncreated": sum(row["summary"]["uncreated"] for row in groups),
            "legacy": sum(row["summary"]["legacy"] for row in groups),
            "free": sum(row["summary"]["free"] for row in groups),
            "reserved": sum(row["summary"]["reserved"] for row in groups),
            "in_use": sum(row["summary"]["in_use"] for row in groups),
            "error": sum(row["summary"]["error"] for row in groups),
            "group_mismatches": sum(row["summary"]["group_mismatches"] for row in groups),
            "topology_incomplete": sum(row["summary"]["topology_incomplete"] for row in groups),
            "expected_enabled_nodes": (
                groups[0]["summary"]["expected_enabled_nodes"] if groups else 0
            ),
            "disabled_nodes": (
                groups[0]["summary"]["disabled_nodes"] if groups else 0
            ),
        },
    }


@app.post("/api/users/preview")
def preview_users(payload: PreviewRequest):
    extension_range = require_provisioning_group(payload.user_group)
    template = get_group_template(payload.user_group)
    if not template:
        raise HTTPException(
            status_code=409,
            detail="El User Group %s no tiene un usuario plantilla configurado" % payload.user_group,
        )

    with db_cursor() as cursor:
        cursor.execute("SELECT user FROM vicidial_users")
        existing = set(str(row["user"]).upper() for row in cursor.fetchall())

    reserved = set()  # type: Set[str]
    results = []

    for index, person in enumerate(payload.people, start=1):
        name = first_name(person.first_names)
        last = normalize_token(person.paternal)
        initial = candidate_for(last, name, 1) if name and last else ""

        if not name or not last:
            results.append({
                "id": index,
                "first_names": person.first_names,
                "paternal": person.paternal,
                "maternal": person.maternal,
                "initial": initial,
                "username": "",
                "status": "CONFLICT",
                "reason": "NAME_OR_LASTNAME_INVALID",
                "resolved": False,
            })
            continue

        chosen = None  # type: Optional[str]
        attempts = []  # type: List[str]

        for prefix_len in range(1, len(last) + 1):
            candidate = candidate_for(last, name, prefix_len)
            if candidate in attempts:
                continue
            attempts.append(candidate)
            if candidate not in existing and candidate not in reserved:
                chosen = candidate
                break

        if chosen is None:
            base = candidate_for(last, name, len(last))
            suffix = 2
            while suffix < 10000:
                suffix_text = str(suffix)
                candidate = "%s%s" % (
                    base[:USERNAME_MAX_LENGTH - len(suffix_text)],
                    suffix_text,
                )
                if candidate not in existing and candidate not in reserved:
                    chosen = candidate
                    break
                suffix += 1

        if chosen is None:
            results.append({
                "id": index,
                "first_names": person.first_names,
                "paternal": person.paternal,
                "maternal": person.maternal,
                "initial": initial,
                "username": "",
                "status": "CONFLICT",
                "reason": "NO_AVAILABLE_USERNAME",
                "resolved": False,
            })
            continue

        reserved.add(chosen)
        results.append({
            "id": index,
            "first_names": person.first_names,
            "paternal": person.paternal,
            "maternal": person.maternal,
            "initial": initial,
            "username": chosen,
            "status": "AVAILABLE",
            "reason": "COLLISION_RESOLVED" if chosen != initial else "AVAILABLE",
            "resolved": chosen != initial,
            "attempts": attempts,
        })

    available_rows = [row for row in results if row["status"] == "AVAILABLE"]
    extension_preview = preview_extension_allocations(
        payload.user_group,
        len(available_rows),
    )
    allocations = list(extension_preview["allocations"])

    allocation_index = 0
    for row in results:
        if row["status"] != "AVAILABLE":
            row["extension"] = None
            row["extension_source"] = None
            row["extension_action"] = None
            continue

        if allocation_index >= len(allocations):
            row["status"] = "CONFLICT"
            row["reason"] = "NO_AVAILABLE_EXTENSION"
            row["extension"] = None
            row["extension_source"] = None
            row["extension_action"] = None
            continue

        allocation = allocations[allocation_index]
        allocation_index += 1
        row["extension"] = allocation["extension"]
        row["extension_source"] = allocation["source"]
        row["extension_action"] = allocation["action"]

    return {
        "template": template,
        "default_password_configured": payload.user_group in load_group_defaults(),
        "extension_range": extension_range,
        "extension_allocation": {
            "requested": extension_preview["requested"],
            "allocated": extension_preview["allocated"],
            "candidates_considered": extension_preview["candidates_considered"],
            "templates_ready": extension_preview.get("templates_ready", False),
            "required_nodes": extension_preview.get("required_nodes", 0),
            "rejected": extension_preview["rejected"],
        },
        "requested": len(payload.people),
        "available": sum(1 for row in results if row["status"] == "AVAILABLE"),
        "resolved": sum(
            1 for row in results
            if row["status"] == "AVAILABLE" and row.get("resolved")
        ),
        "conflicts": sum(1 for row in results if row["status"] != "AVAILABLE"),
        "users": results,
    }


@app.post("/api/provisioning/write-plan")
def provisioning_write_plan_route(payload: WritePlanRequest):
    return provisioning_write_plan(
        payload.user_group,
        payload.username,
        payload.full_name,
        payload.extension,
    )


@app.post("/api/users/create")
def create_users(payload: CreateRequest):
    require_provisioning_group(payload.user_group)
    if not CREATE_ENABLED:
        raise HTTPException(
            status_code=403,
            detail=(
                "Creación deshabilitada. CP1 sólo consulta vici222; "
                "habilite escritura únicamente después de validar el método de provisión."
            ),
        )

    # Resuelve la contraseña aquí, en servidor. Nunca imprimirla, registrarla ni devolverla.
    _agent_pass = resolve_agent_password(payload.user_group, payload.agent_pass)
    del _agent_pass

    raise HTTPException(
        status_code=501,
        detail="CP1 conectado. Motor de creación pendiente de CP2.",
    )


@app.get("/")
def index():
    index_file = APP_ROOT / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="index.html no encontrado")
    return FileResponse(str(index_file))
