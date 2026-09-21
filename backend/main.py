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
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "VICI_USERS_CORS_ORIGINS",
        "https://teamdirecto.github.io",
    ).split(",")
    if origin.strip()
]

app = FastAPI(title="Vici-Users API", version="0.11.0-canonical-phone-plan")
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

    return {
        "template": template,
        "default_password_configured": payload.user_group in load_group_defaults(),
        "extension_range": extension_range,
        "requested": len(payload.people),
        "available": sum(1 for row in results if row["status"] == "AVAILABLE"),
        "resolved": sum(1 for row in results if row.get("resolved")),
        "conflicts": sum(1 for row in results if row["status"] != "AVAILABLE"),
        "users": results,
    }


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
