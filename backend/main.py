from __future__ import annotations

import os
import re
import socket
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

import pymysql
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

APP_ROOT = Path(__file__).resolve().parent.parent
ASTGUI_CONF = Path(os.getenv("ASTGUI_CONF", "/etc/astguiclient.conf"))
CREATE_ENABLED = os.getenv("VICI_USERS_ENABLE_CREATE", "false").lower() in {"1", "true", "yes", "y"}
USERNAME_MAX_LENGTH = int(os.getenv("VICI_USERS_USERNAME_MAX_LENGTH", "20"))

app = FastAPI(title="Vici-Users API", version="0.2.0")


def _read_astguiclient_conf() -> dict[str, str]:
    values: dict[str, str] = {}
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


def db_config() -> dict:
    conf = _read_astguiclient_conf()
    host = os.getenv("VICI_DB_HOST", conf.get("host", "127.0.0.1"))
    database = os.getenv("VICI_DB_NAME", conf.get("database", "asterisk"))
    user = os.getenv("VICI_DB_USER", conf.get("user", "cron"))
    password = os.getenv("VICI_DB_PASS", conf.get("password", ""))
    port = int(os.getenv("VICI_DB_PORT", conf.get("port", "3306") or "3306"))

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
    except pymysql.MySQLError as exc:
        raise HTTPException(status_code=503, detail=f"No fue posible consultar VICIdial DB: {exc}") from exc
    finally:
        if connection:
            connection.close()


def normalize_token(value: str) -> str:
    text = unicodedata.normalize("NFD", value or "")
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    text = text.replace("Ñ", "N").replace("ñ", "n")
    return re.sub(r"[^A-Za-z0-9]", "", text).upper()


def first_name(value: str) -> str:
    parts = (value or "").strip().split()
    return normalize_token(parts[0]) if parts else ""


def candidate_for(last_name: str, name: str, prefix_len: int) -> str:
    raw = f"{last_name[:prefix_len]}{name}"
    return raw[:USERNAME_MAX_LENGTH]


class PersonIn(BaseModel):
    first_names: str = Field(min_length=1, max_length=120)
    paternal: str = Field(min_length=1, max_length=80)
    maternal: str = Field(default="", max_length=80)


class PreviewRequest(BaseModel):
    template_user: str = Field(min_length=1, max_length=20)
    user_group: str = Field(min_length=1, max_length=20)
    people: list[PersonIn] = Field(min_length=1, max_length=500)


class CreateRequest(PreviewRequest):
    usernames: list[str] = Field(min_length=1, max_length=500)


@app.get("/api/health")
def health():
    db_ok = False
    db_host = db_config()["host"]
    try:
        with db_cursor() as cursor:
            cursor.execute("SELECT 1 AS ok")
            db_ok = cursor.fetchone()["ok"] == 1
    except HTTPException:
        db_ok = False

    return {
        "status": "ok" if db_ok else "degraded",
        "node": socket.gethostname(),
        "target": "EHECTO",
        "db_host": db_host,
        "db_ok": db_ok,
        "create_enabled": CREATE_ENABLED,
        "username_max_length": USERNAME_MAX_LENGTH,
    }


@app.get("/api/groups")
def groups():
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
        return {"groups": cursor.fetchall()}


@app.get("/api/groups/{user_group}/users")
def group_users(user_group: str):
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
def user_detail(user: str):
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
            raise HTTPException(status_code=404, detail="Usuario plantilla no encontrado")
        return row


@app.post("/api/users/preview")
def preview_users(payload: PreviewRequest):
    with db_cursor() as cursor:
        cursor.execute(
            "SELECT user, user_group, user_level, active FROM vicidial_users WHERE user=%s LIMIT 1",
            (payload.template_user,),
        )
        template = cursor.fetchone()
        if not template:
            raise HTTPException(status_code=404, detail="Usuario plantilla no encontrado")
        if template["user_group"] != payload.user_group:
            raise HTTPException(status_code=400, detail="El usuario plantilla no pertenece al User Group seleccionado")

        cursor.execute("SELECT user FROM vicidial_users")
        existing = {str(row["user"]).upper() for row in cursor.fetchall()}

    reserved: set[str] = set()
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

        chosen: Optional[str] = None
        attempts: list[str] = []
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
                candidate = f"{base[:USERNAME_MAX_LENGTH-len(suffix_text)]}{suffix_text}"
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
        "requested": len(payload.people),
        "available": sum(1 for row in results if row["status"] == "AVAILABLE"),
        "resolved": sum(1 for row in results if row.get("resolved")),
        "conflicts": sum(1 for row in results if row["status"] != "AVAILABLE"),
        "users": results,
    }


@app.post("/api/users/create")
def create_users(payload: CreateRequest):
    if not CREATE_ENABLED:
        raise HTTPException(
            status_code=403,
            detail="Creación deshabilitada. Validación/preview están activos; habilite VICI_USERS_ENABLE_CREATE cuando el método de provisión haya sido aprobado.",
        )

    # Protección intencional: CP1 conecta lectura y preview contra datos reales.
    # La escritura se implementará en el siguiente checkpoint usando el método
    # de provisión VICIdial acordado (API + clonación controlada de plantilla).
    raise HTTPException(status_code=501, detail="CP1 conectado. Motor de creación pendiente de habilitar en CP2.")


@app.get("/")
def index():
    index_file = APP_ROOT / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="index.html no encontrado")
    return FileResponse(index_file)
