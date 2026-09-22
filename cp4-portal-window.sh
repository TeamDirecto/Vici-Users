#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_HOST="vici97"
APP="/opt/vici-users"
CFG="/etc/sysconfig/vici-users"
API="http://127.0.0.1:8094"
PY="${APP}/.venv/bin/python"
DB="/var/lib/vici-users/extension_inventory.db"

WINDOW_SECONDS="${1:-600}"
POLL_SECONDS=2

log(){ printf '\033[1;34m[CP4]\033[0m %s\n' "$*"; }
ok(){ printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
die(){ printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Ejecuta como root"
[ "$(hostname -s 2>/dev/null || hostname)" = "$EXPECTED_HOST" ] || die "Sólo válido en vici97"
[ -f "$CFG" ] || die "No existe $CFG"
[ -x "$PY" ] || die "No existe $PY"
[ -f "$DB" ] || die "No existe $DB"

case "$WINDOW_SECONDS" in
  ''|*[!0-9]*) die "WINDOW_SECONDS debe ser entero" ;;
esac

[ "$WINDOW_SECONDS" -ge 60 ] || die "Ventana mínima: 60 segundos"
[ "$WINDOW_SECONDS" -le 1800 ] || die "Ventana máxima: 1800 segundos"

set_cfg(){
    key="$1"
    value="$2"

    if grep -q "^${key}=" "$CFG"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$CFG"
    else
        printf '%s=%s\n' "$key" "$value" >> "$CFG"
    fi
}

wait_api(){
    for i in $(seq 1 30); do
        if curl -fsS --connect-timeout 1 "$API/api/health" > /tmp/vici-users-cp4-health.json 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

close_gate(){
    set +e
    log "Cerrando ventana de escritura del portal..."

    set_cfg "VICI_USERS_ENABLE_CREATE" "false"
    set_cfg "VICI_USERS_PORTAL_WRITE_ENABLED" "false"
    set_cfg "VICI_USERS_WRITE_EXECUTOR_ENABLED" "false"

    systemctl restart vici-users >/dev/null 2>&1

    if wait_api; then
        "$PY" - <<'PY'
import json

with open("/tmp/vici-users-cp4-health.json") as fh:
    h=json.load(fh)

print(
    "[SAFETY] create_enabled=%s portal_write_enabled=%s write_executor_enabled=%s"
    % (
        h.get("create_enabled"),
        h.get("portal_write_enabled"),
        h.get("write_executor_enabled"),
    )
)

assert h.get("create_enabled") is False
assert h.get("portal_write_enabled") is False
assert h.get("write_executor_enabled") is False
PY
    else
        warn "No fue posible validar health después del cierre"
        systemctl --no-pager --full status vici-users || true
    fi

    set -e
}

cleanup(){
    rc=$?
    trap - EXIT INT TERM
    close_gate
    exit "$rc"
}

trap cleanup EXIT INT TERM

log "Forzando estado inicial seguro..."
set_cfg "VICI_USERS_ENABLE_CREATE" "false"
set_cfg "VICI_USERS_PORTAL_WRITE_ENABLED" "false"
set_cfg "VICI_USERS_WRITE_EXECUTOR_ENABLED" "false"

systemctl restart vici-users
wait_api || die "Backend no respondió en estado seguro"

log "Validando health y topología 4/4 (.94 excluido)..."
cd "$APP"
"$PY" - <<'PY'
import json

from backend.main import load_cluster_nodes

with open("/tmp/vici-users-cp4-health.json") as fh:
    h=json.load(fh)

assert h.get("db_ok") is True, "db_ok != true"
assert h.get("cluster_topology_ok") is True, "cluster_topology_ok != true"
assert h.get("provisioning_nodes_count") == 4, "se requieren 4 nodos habilitados"
assert h.get("disabled_nodes_count") == 1, "se requiere exactamente 1 nodo deshabilitado"
assert h.get("operators_configured") is True, "no hay operadores configurados"
assert h.get("create_enabled") is False, "CREATE debe iniciar false"
assert h.get("portal_write_enabled") is False, "PORTAL_WRITE debe iniciar false"
assert h.get("write_executor_enabled") is False, "EXECUTOR local debe iniciar false"

topology = load_cluster_nodes()
enabled = sorted(
    str(node["server_ip"])
    for node in topology["nodes"]
    if node["enabled"]
)
disabled = sorted(
    str(node["server_ip"])
    for node in topology["nodes"]
    if not node["enabled"]
)

expected_enabled = sorted([
    "172.20.20.233",
    "172.20.21.90",
    "172.20.21.96",
    "172.20.20.110",
])

assert enabled == expected_enabled, "topología habilitada inesperada: %s" % enabled
assert disabled == ["172.20.21.94"], ".94 debe ser el único nodo excluido: %s" % disabled

print("[OK] DB y topología 4/4; 172.20.21.94 excluido")
PY

log "Validando phones + phones_alias de extensiones administradas por el portal..."
"$PY" - <<'PY'
import sqlite3

from backend.main import db_cursor, load_cluster_nodes

DB = "/var/lib/vici-users/extension_inventory.db"
topology = load_cluster_nodes()
enabled_nodes = [
    node for node in topology["nodes"] if node["enabled"]
]
enabled = set(node["server_ip"] for node in enabled_nodes)

local = sqlite3.connect(DB)
local.row_factory = sqlite3.Row
try:
    managed = local.execute(
        """
        SELECT extension, user_group, current_user, status
          FROM extension_inventory
         WHERE status='IN_USE'
         ORDER BY user_group, extension
        """
    ).fetchall()
finally:
    local.close()

bad = []

with db_cursor() as cursor:
    for item in managed:
        extension = str(item["extension"])
        group = str(item["user_group"])

        cursor.execute(
            """
            SELECT extension, server_ip, user_group, active
              FROM phones
             WHERE extension=%s
             ORDER BY server_ip
            """,
            (extension,),
        )
        rows = cursor.fetchall()

        by_server = {}
        for row in rows:
            server = str(row.get("server_ip") or "")
            if server:
                by_server[server] = row

        missing = sorted(enabled.difference(set(by_server)))
        wrong_group = sorted(
            server
            for server, row in by_server.items()
            if server in enabled
            and str(row.get("user_group") or "") != group
        )
        inactive = sorted(
            server
            for server, row in by_server.items()
            if server in enabled
            and str(row.get("active") or "").upper() != "Y"
        )

        cursor.execute(
            """
            SELECT alias_id, alias_name, logins_list, user_group
              FROM phones_alias
             WHERE alias_id=%s
             LIMIT 1
            """,
            (extension,),
        )
        alias = cursor.fetchone()

        expected_logins = [
            extension + str(node["login_suffix"])
            for node in enabled_nodes
        ]
        alias_missing = alias is None
        alias_identity_bad = False
        alias_missing_logins = []
        alias_actual_logins = []

        if alias:
            alias_actual_logins = [
                value.strip()
                for value in str(alias.get("logins_list") or "").split(",")
                if value.strip()
            ]
            alias_identity_bad = (
                str(alias.get("alias_id") or "") != extension
                or str(alias.get("alias_name") or "") != extension
                or str(alias.get("user_group") or "") != "---ALL---"
            )
            alias_missing_logins = [
                login for login in expected_logins
                if login not in alias_actual_logins
            ]

        if (
            missing
            or wrong_group
            or inactive
            or alias_missing
            or alias_identity_bad
            or alias_missing_logins
        ):
            bad.append(
                (
                    group,
                    extension,
                    item["current_user"],
                    missing,
                    wrong_group,
                    inactive,
                    alias_missing,
                    alias_identity_bad,
                    alias_missing_logins,
                    alias_actual_logins,
                )
            )

if bad:
    print("[ERROR] Hay extensiones IN_USE del portal con phones/alias incompletos:")
    for (
        group,
        extension,
        user,
        missing,
        wrong_group,
        inactive,
        alias_missing,
        alias_identity_bad,
        alias_missing_logins,
        alias_actual_logins,
    ) in bad:
        print("")
        print("  grupo          :", group)
        print("  extension      :", extension)
        print("  usuario        :", user)
        print("  phones faltan  :", ",".join(missing) or "-")
        print("  otro grupo     :", ",".join(wrong_group) or "-")
        print("  phones inactivos:", ",".join(inactive) or "-")
        print("  alias ausente  :", alias_missing)
        print("  alias identidad:", "ERROR" if alias_identity_bad else "OK")
        print("  alias logins faltantes:", ",".join(alias_missing_logins) or "-")
        print("  alias logins actuales :", ",".join(alias_actual_logins) or "-")
    raise SystemExit(20)

print(
    "[OK] %d extensión(es) IN_USE sanas en phones 4/4 y phones_alias"
    % len(managed)
)
PY

BASELINE_ID="$(
sqlite3 "$DB" "SELECT COALESCE(MAX(id),0) FROM auth_audit;"
)"

log "Abriendo ventana CP4 por ${WINDOW_SECONDS}s..."
set_cfg "VICI_USERS_ENABLE_CREATE" "true"
set_cfg "VICI_USERS_PORTAL_WRITE_ENABLED" "true"
set_cfg "VICI_USERS_WRITE_EXECUTOR_ENABLED" "false"

systemctl restart vici-users
wait_api || die "Backend no respondió al abrir CP4"

"$PY" - <<'PY'
import json

from backend.main import load_cluster_nodes

with open("/tmp/vici-users-cp4-health.json") as fh:
    h=json.load(fh)

assert h.get("create_enabled") is True
assert h.get("portal_write_enabled") is True
assert h.get("write_executor_enabled") is False
assert h.get("provisioning_nodes_count") == 4
assert h.get("disabled_nodes_count") == 1

topology = load_cluster_nodes()
disabled = sorted(
    str(node["server_ip"])
    for node in topology["nodes"]
    if not node["enabled"]
)
assert disabled == ["172.20.21.94"]

print("[OK] CREATE=true / PORTAL_WRITE=true / EXECUTOR_LOCAL=false / NODOS=4 / .94=EXCLUIDO")
PY

echo
echo "============================================================"
echo " CP4 ABIERTO"
echo "============================================================"
echo " Portal : https://teamdirecto.github.io/Vici-Users/"
echo " Tiempo : ${WINDOW_SECONDS} segundos"
echo " Nodos  : 4 operativos; 172.20.21.94 excluido temporalmente"
echo " Regla  : una sola alta / extensión UNCREATED / admin"
echo " Cierre : automático al primer resultado o por timeout"
echo "============================================================"
echo

START_TS="$(date +%s)"
DEADLINE=$((START_TS + WINDOW_SECONDS))

while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    ROW="$(
        sqlite3 -separator '|' "$DB" "
        SELECT id,event_type,COALESCE(username,''),COALESCE(detail,'')
          FROM auth_audit
         WHERE id > $BASELINE_ID
           AND event_type IN (
               'PROVISIONING_SUCCESS',
               'PROVISIONING_BLOCKED',
               'PROVISIONING_FAILED'
           )
         ORDER BY id
         LIMIT 1;
        "
    )"

    if [ -n "$ROW" ]; then
        EVENT_ID="$(printf '%s' "$ROW" | cut -d'|' -f1)"
        EVENT_TYPE="$(printf '%s' "$ROW" | cut -d'|' -f2)"
        EVENT_USER="$(printf '%s' "$ROW" | cut -d'|' -f3)"
        EVENT_DETAIL="$(printf '%s' "$ROW" | cut -d'|' -f4-)"

        echo
        log "Resultado detectado: $EVENT_TYPE"
        echo "id       : $EVENT_ID"
        echo "operador : $EVENT_USER"
        echo "detalle  : $EVENT_DETAIL"

        if [ "$EVENT_TYPE" = "PROVISIONING_SUCCESS" ]; then
            ok "Alta completada; cerrando CP4"
            exit 0
        fi

        warn "La operación no terminó en SUCCESS; cerrando CP4"
        exit 30
    fi

    sleep "$POLL_SECONDS"
done

warn "Timeout de la ventana CP4; no se detectó operación terminal"
exit 40
