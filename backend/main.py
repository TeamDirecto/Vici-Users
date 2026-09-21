import json
import os
import re
import socket
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
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "VICI_USERS_CORS_ORIGINS",
        "https://teamdirecto.github.io",
    ).split(",")
    if origin.strip()
]

app = FastAPI(title="Vici-Users API", version="0.7.1-inactive-base-template-fix")
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


def require_managed_group(user_group):
    managed = set(load_managed_groups())
    if user_group not in managed:
        raise HTTPException(
            status_code=403,
            detail="El User Group %s no está autorizado para el flujo de clonación" % user_group,
        )


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
    }


@app.get("/api/groups")
def groups():
    templates = load_group_templates()
    defaults = load_group_defaults()
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
    return {"groups": rows}


@app.get("/api/groups/{user_group}/template")
def group_template(user_group):
    require_managed_group(user_group)
    templates = load_group_templates()
    defaults = load_group_defaults()
    configured_user = templates.get(user_group)
    if not configured_user:
        return {
            "user_group": user_group,
            "configured": False,
            "default_password_configured": user_group in defaults,
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


@app.post("/api/users/preview")
def preview_users(payload: PreviewRequest):
    require_managed_group(payload.user_group)
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
        "requested": len(payload.people),
        "available": sum(1 for row in results if row["status"] == "AVAILABLE"),
        "resolved": sum(1 for row in results if row.get("resolved")),
        "conflicts": sum(1 for row in results if row["status"] != "AVAILABLE"),
        "users": results,
    }


@app.post("/api/users/create")
def create_users(payload: CreateRequest):
    require_managed_group(payload.user_group)
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
