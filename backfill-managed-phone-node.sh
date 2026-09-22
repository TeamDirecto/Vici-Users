#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_HOST="vici97"
APP="/opt/vici-users"
PY="${APP}/.venv/bin/python"

GROUP="${1:-CC-CORTIZO-VW}"
EXTENSION="${2:-95217}"
TARGET_SERVER="${3:-172.20.21.94}"

[ "$(id -u)" -eq 0 ] || { echo "[ERROR] Ejecuta como root" >&2; exit 1; }
[ "$(hostname -s 2>/dev/null || hostname)" = "$EXPECTED_HOST" ] || {
  echo "[ERROR] Sólo válido en vici97" >&2
  exit 1
}
[ -x "$PY" ] || { echo "[ERROR] No existe $PY" >&2; exit 1; }

cd "$APP"

"$PY" - "$GROUP" "$EXTENSION" "$TARGET_SERVER" <<'PY'
from __future__ import print_function

import sys
import sqlite3

import pymysql

from backend.main import (
    canonical_phone_plan,
    db_config,
    db_cursor,
    load_extension_ranges,
)

group, extension, target_server = sys.argv[1:4]

if group not in load_extension_ranges():
    raise SystemExit("[ERROR] Grupo sin bloque de extensiones configurado: %s" % group)

identity = canonical_phone_plan(group, extension)
target = None
for node in identity["nodes"]:
    if node["server_ip"] == target_server:
        target = node
        break

if not target:
    raise SystemExit("[ERROR] El servidor objetivo no existe en cluster_nodes.json")

if not target.get("enabled"):
    raise SystemExit("[ERROR] El servidor objetivo sigue disabled en cluster_nodes.json")

expected_login = target["login"]
expected_dialplan = target["dialplan_number"]

inventory_db = "/var/lib/vici-users/extension_inventory.db"
local = sqlite3.connect(inventory_db)
local.row_factory = sqlite3.Row
try:
    tracked = local.execute(
        """
        SELECT extension, user_group, status, current_user
          FROM extension_inventory
         WHERE extension=?
        """,
        (extension,),
    ).fetchone()
finally:
    local.close()

if not tracked:
    raise SystemExit("[ERROR] La extensión no está administrada por el portal")

if str(tracked["status"]).upper() != "IN_USE":
    raise SystemExit("[ERROR] Estado local inesperado: %s" % tracked["status"])

if str(tracked["user_group"]) != group:
    raise SystemExit(
        "[ERROR] El inventario local pertenece a otro grupo: %s"
        % tracked["user_group"]
    )

print("")
print("============================================================")
print(" BACKFILL DE NODO")
print("============================================================")
print(" Grupo       :", group)
print(" Extensión   :", extension)
print(" Usuario     :", tracked["current_user"])
print(" Servidor    :", target_server)
print(" Login nuevo :", expected_login)
print(" Dialplan    :", expected_dialplan)
print("============================================================")
print("")

with db_cursor() as cursor:
    cursor.execute(
        """
        SELECT extension, server_ip, login, dialplan_number,
               voicemail_id, status, active, fullname, user_group
          FROM phones
         WHERE extension=%s
         ORDER BY server_ip
        """,
        (extension,),
    )
    existing = cursor.fetchall()

    existing_servers = set(str(row["server_ip"]) for row in existing)

    if target_server in existing_servers:
        raise SystemExit(
            "[ERROR] Ya existe %s en %s; no se toca nada"
            % (extension, target_server)
        )

    expected_other = set(
        node["server_ip"]
        for node in identity["nodes"]
        if node["enabled"] and node["server_ip"] != target_server
    )
    present_other = existing_servers.intersection(expected_other)

    if present_other != expected_other:
        missing = sorted(expected_other.difference(existing_servers))
        raise SystemExit(
            "[ERROR] Antes del backfill faltan otros nodos además del objetivo: %s"
            % ",".join(missing)
        )

    for row in existing:
        if str(row.get("user_group") or "") != group:
            raise SystemExit("[ERROR] La extensión ya tiene filas en otro user_group")
        if str(row.get("active") or "").upper() != "Y":
            raise SystemExit(
                "[ERROR] Existe una fila previa no activa en %s"
                % row.get("server_ip")
            )

    cursor.execute(
        """
        SELECT extension, server_ip, login, dialplan_number,
               voicemail_id, status, active, fullname, user_group,
               protocol, template_id, phone_context, ext_context,
               is_webphone, LENGTH(conf_secret) AS conf_secret_len
          FROM phones
         WHERE user_group=%s
           AND server_ip=%s
           AND active='Y'
         ORDER BY extension
         LIMIT 1
        """,
        (group, target_server),
    )
    source_meta = cursor.fetchone()

    if not source_meta:
        raise SystemExit(
            "[ERROR] No hay plantilla activa del grupo en %s" % target_server
        )

    if not source_meta.get("template_id"):
        raise SystemExit("[ERROR] La plantilla no tiene template_id")

    if int(source_meta.get("conf_secret_len") or 0) <= 0:
        raise SystemExit("[ERROR] La plantilla no tiene conf_secret")

    source_extension = str(source_meta["extension"])

    cursor.execute(
        """
        SELECT extension, server_ip, login
          FROM phones
         WHERE login=%s
        """,
        (expected_login,),
    )
    if cursor.fetchall():
        raise SystemExit("[ERROR] Colisión de login: %s" % expected_login)

    cursor.execute(
        """
        SELECT extension, server_ip, dialplan_number
          FROM phones
         WHERE dialplan_number=%s
        """,
        (expected_dialplan,),
    )
    if cursor.fetchall():
        raise SystemExit("[ERROR] Colisión de dialplan: %s" % expected_dialplan)

    cursor.execute("SHOW COLUMNS FROM phones")
    phone_columns = [row["Field"] for row in cursor.fetchall()]

print("[OK] Precheck")
print("     plantilla :", source_extension)
print("     login src :", source_meta["login"])
print("     dial src  :", source_meta["dialplan_number"])
print("     target    :", expected_login, "/", expected_dialplan)

override_values = {
    "extension": extension,
    "dialplan_number": expected_dialplan,
    "voicemail_id": extension,
    "phone_ip": None,
    "computer_ip": None,
    "server_ip": target_server,
    "login": expected_login,
    "pass": extension,
    "status": "ACTIVE",
    "active": "N",
    "messages": 0,
    "old_messages": 0,
    "login_user": None,
    "login_pass": None,
    "login_campaign": None,
    "user_group": group,
    "peer_status": "UNKNOWN",
    "ping_time": None,
}

source_fullname = str(source_meta.get("fullname") or "")
if source_extension and source_extension in source_fullname:
    override_values["fullname"] = source_fullname.replace(
        source_extension,
        extension,
    )
else:
    override_values["fullname"] = "ext %s" % extension

select_parts = []
params = []

for field in phone_columns:
    if field in override_values:
        select_parts.append("%s AS `%s`" % ("%s", field))
        params.append(override_values[field])
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

params.extend([source_extension, target_server])

inserted = False
connection = None

def compensate():
    cfg = db_config()
    cfg["autocommit"] = True
    conn = pymysql.connect(**cfg)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            DELETE FROM phones
             WHERE extension=%s
               AND server_ip=%s
               AND login=%s
               AND user_group=%s
            """,
            (extension, target_server, expected_login, group),
        )
        print("[COMPENSATE] filas eliminadas:", cur.rowcount)
    finally:
        conn.close()

try:
    cfg = db_config()
    cfg["autocommit"] = True
    connection = pymysql.connect(**cfg)
    cursor = connection.cursor()

    cursor.execute(insert_sql, tuple(params))
    if cursor.rowcount != 1:
        raise RuntimeError("INSERT rowcount=%s" % cursor.rowcount)
    inserted = True

    print("[OK] Insert staged active=N")

    cursor.execute(
        """
        SELECT extension, server_ip, login, dialplan_number,
               voicemail_id, status, active, fullname, user_group,
               template_id, is_webphone,
               LENGTH(conf_secret) AS conf_secret_len
          FROM phones
         WHERE extension=%s
           AND server_ip=%s
        """,
        (extension, target_server),
    )
    staged = cursor.fetchone()

    if not staged:
        raise RuntimeError("No se encontró la fila staged")

    checks = {
        "extension": extension,
        "server_ip": target_server,
        "login": expected_login,
        "dialplan_number": expected_dialplan,
        "voicemail_id": extension,
        "status": "ACTIVE",
        "active": "N",
        "fullname": "ext %s" % extension,
        "user_group": group,
        "template_id": "webRTC",
        "is_webphone": "Y",
    }

    for field, expected in checks.items():
        actual = str(staged.get(field) or "")
        if actual != str(expected):
            raise RuntimeError(
                "STAGED_MISMATCH %s expected=%s actual=%s"
                % (field, expected, actual)
            )

    if int(staged.get("conf_secret_len") or 0) <= 0:
        raise RuntimeError("STAGED conf_secret vacío")

    print("[OK] Stage validado")

    cursor.execute(
        """
        UPDATE phones
           SET active='Y'
         WHERE extension=%s
           AND server_ip=%s
           AND login=%s
           AND user_group=%s
           AND active='N'
        """,
        (extension, target_server, expected_login, group),
    )

    if cursor.rowcount != 1:
        raise RuntimeError("ACTIVATE rowcount=%s" % cursor.rowcount)

    cursor.execute(
        """
        SELECT extension, server_ip, login, dialplan_number,
               voicemail_id, status, active, fullname, user_group,
               template_id, is_webphone,
               LENGTH(conf_secret) AS conf_secret_len
          FROM phones
         WHERE extension=%s
           AND server_ip=%s
        """,
        (extension, target_server),
    )
    final = cursor.fetchone()

    if not final or str(final.get("active") or "") != "Y":
        raise RuntimeError("Validación final falló")

    print("[OK] Nodo activado")
    print("")
    print("RESULTADO")
    print("---------")
    print(
        "%s  %s  %s  %s  active=%s template=%s webphone=%s conf_secret_len=%s"
        % (
            final["extension"],
            final["server_ip"],
            final["login"],
            final["dialplan_number"],
            final["active"],
            final["template_id"],
            final["is_webphone"],
            final["conf_secret_len"],
        )
    )
    print("")
    print("[SUCCESS] Backfill completado")

except Exception as exc:
    print("[ERROR] %s: %s" % (exc.__class__.__name__, exc))
    if inserted:
        try:
            compensate()
            print("[OK] Compensación ejecutada")
        except Exception as cexc:
            print(
                "[CRITICAL] Falló la compensación: %s: %s"
                % (cexc.__class__.__name__, cexc)
            )
    raise
finally:
    if connection:
        connection.close()
PY
