#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="vici-users"
APP_DIR="/opt/vici-users"
REPO_URL="https://github.com/TeamDirecto/Vici-Users.git"
EXPECTED_HOSTNAME="vici97"
ASTGUI_CONF="/etc/astguiclient.conf"
DB_HOST="172.20.20.198"
DB_NAME="asterisk"
PORT="8094"
INVENTORY_DIR="/var/lib/vici-users"
INVENTORY_DB="${INVENTORY_DIR}/extension_inventory.db"
SERVICE_NAME="vici-users.service"
SERVICE_DST="/etc/systemd/system/${SERVICE_NAME}"
ENV_DST="/etc/sysconfig/vici-users"
INSTALL_SERVICE=0
START_SERVICE=0
SKIP_PIP=0

usage() {
  cat <<'EOF'
Vici-Users bootstrap - EHECTO / vici97

Uso:
  ./bootstrap.sh [opciones]

Opciones:
  --install-service   Instala/actualiza el unit de systemd después de validar CP1.
  --start-service     Instala y además habilita/inicia el servicio.
  --skip-pip          No ejecuta pip install (útil si el venv ya está preparado).
  -h, --help          Muestra esta ayuda.

Seguridad CP1:
  - No actualiza Python del sistema.
  - No instala gcc/make ni paquetes del SO.
  - No modifica /etc/astguiclient.conf.
  - Fuerza DB destino 172.20.20.198 (vici222).
  - VICI_USERS_ENABLE_CREATE=false.
  - Hace sólo lecturas de validación contra VICIdial.
EOF
}

log()  { printf '\033[1;34m[BOOTSTRAP]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --install-service) INSTALL_SERVICE=1 ;;
    --start-service) INSTALL_SERVICE=1; START_SERVICE=1 ;;
    --skip-pip) SKIP_PIP=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Opción desconocida: $1" ;;
  esac
  shift
done

CURRENT_HOST="$(hostname -s 2>/dev/null || hostname)"
[ "$CURRENT_HOST" = "$EXPECTED_HOSTNAME" ] || die "Este bootstrap está blindado para ${EXPECTED_HOSTNAME}; host actual: ${CURRENT_HOST}"

[ -f "$ASTGUI_CONF" ] || die "No existe ${ASTGUI_CONF}"
command -v python3 >/dev/null 2>&1 || die "python3 no está disponible"
command -v curl >/dev/null 2>&1 || die "curl no está disponible"
command -v git >/dev/null 2>&1 || die "git no está disponible"

PYVER="$(python3 -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
log "Host: ${CURRENT_HOST}"
log "Python del sistema: ${PYVER} (no será modificado)"

case "$PYVER" in
  3.6.*) ok "Python 3.6 detectado; se usará stack compatible fijado en requirements.txt" ;;
  *) warn "Python ${PYVER}; el proyecto fue validado originalmente con 3.6.13. Continuando con el runtime disponible." ;;
esac

conf_value() {
  key="$1"
  awk -F'=>' -v k="$key" '$1 ~ "^[[:space:]]*" k "[[:space:]]*$" {gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit}' "$ASTGUI_CONF"
}

CONF_DB_HOST="$(conf_value VARDB_server)"
CONF_DB_NAME="$(conf_value VARDB_database)"
CONF_DB_USER="$(conf_value VARDB_user)"
CONF_DB_PORT="$(conf_value VARDB_port)"

[ "$CONF_DB_HOST" = "$DB_HOST" ] || die "VARDB_server=${CONF_DB_HOST}; se esperaba ${DB_HOST} (vici222)"
[ "$CONF_DB_NAME" = "$DB_NAME" ] || die "VARDB_database=${CONF_DB_NAME}; se esperaba ${DB_NAME}"
[ -n "$CONF_DB_USER" ] || die "VARDB_user está vacío"
[ -n "$CONF_DB_PORT" ] || CONF_DB_PORT="3306"

ok "astguiclient.conf apunta a vici222: ${CONF_DB_HOST}/${CONF_DB_NAME} usuario=${CONF_DB_USER} puerto=${CONF_DB_PORT}"

if [ "$(pwd -P)" != "$APP_DIR" ]; then
  if [ -d "$APP_DIR/.git" ]; then
    log "Usando checkout existente en ${APP_DIR}"
    cd "$APP_DIR"
  elif [ -d .git ] && [ -f backend/main.py ]; then
    warn "Bootstrap ejecutado desde $(pwd -P), no desde ${APP_DIR}. Se usará el checkout actual para validación."
    APP_DIR="$(pwd -P)"
  else
    die "Ejecuta este bootstrap desde el repo Vici-Users o clónalo en ${APP_DIR}: git clone ${REPO_URL} ${APP_DIR}"
  fi
fi

[ -f backend/main.py ] || die "No existe backend/main.py en ${APP_DIR}"
[ -f backend/requirements.txt ] || die "No existe backend/requirements.txt"

if ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${PORT}$"; then
  if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    warn "Puerto ${PORT} ya está ocupado por ${SERVICE_NAME}; se omite prueba temporal y se validará el servicio existente."
    PORT_BUSY_BY_SERVICE=1
  else
    die "Puerto ${PORT} ya está ocupado por otro proceso"
  fi
else
  PORT_BUSY_BY_SERVICE=0
fi

if [ ! -x .venv/bin/python ]; then
  log "Creando venv independiente en ${APP_DIR}/.venv"
  python3 -m venv .venv || die "No fue posible crear el venv con python3 -m venv"
else
  ok "Venv existente detectado"
fi

[ -x .venv/bin/python ] || die "El venv no contiene python"
[ -x .venv/bin/pip ] || die "El venv no contiene pip"

if [ "$SKIP_PIP" -eq 0 ]; then
  log "Instalando dependencias fijadas (sin actualizar pip del sistema)"
  PIP_DISABLE_PIP_VERSION_CHECK=1 .venv/bin/pip install -r backend/requirements.txt
else
  warn "--skip-pip activo: no se instalaron dependencias"
fi

log "Validando sintaxis e imports"
.venv/bin/python -m py_compile backend/main.py
.venv/bin/python - <<'PY'
import sys
import fastapi, uvicorn, pydantic, starlette, pymysql
from backend.main import app
print("Python   :", sys.version.split()[0])
print("FastAPI  :", fastapi.__version__)
print("Uvicorn  :", uvicorn.__version__)
print("Pydantic :", pydantic.__version__)
print("Starlette:", starlette.__version__)
print("PyMySQL  :", pymysql.__version__)
print("App      :", app.title, app.version)
PY
ok "Backend importable"

TMP_ENV="$(mktemp)"
TMP_LOG="$(mktemp)"
cleanup() {
  if [ -n "${TEST_PID:-}" ] && kill -0 "$TEST_PID" 2>/dev/null; then
    kill "$TEST_PID" 2>/dev/null || true
    wait "$TEST_PID" 2>/dev/null || true
  fi
  rm -f "$TMP_ENV" "$TMP_LOG"
}
trap cleanup EXIT

cat > "$TMP_ENV" <<EOF
ASTGUI_CONF=${ASTGUI_CONF}
VICI_DB_HOST=${DB_HOST}
VICI_DB_EXPECTED_HOST=${DB_HOST}
VICI_DB_NAME=${DB_NAME}
VICI_USERS_ENABLE_CREATE=false
VICI_USERS_USERNAME_MAX_LENGTH=20
VICI_USERS_INVENTORY_DB=/tmp/vici-users-extension-inventory.db
EOF

if [ "$PORT_BUSY_BY_SERVICE" -eq 0 ]; then
  log "Levantando prueba temporal en 127.0.0.1:${PORT}"
  set -a
  . "$TMP_ENV"
  set +a
  .venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port "$PORT" >"$TMP_LOG" 2>&1 &
  TEST_PID=$!

  HEALTH_OK=0
  i=0
  while [ "$i" -lt 20 ]; do
    if curl -fsS "http://127.0.0.1:${PORT}/api/health" >/tmp/vici-users-health.json 2>/dev/null; then
      HEALTH_OK=1
      break
    fi
    if ! kill -0 "$TEST_PID" 2>/dev/null; then
      break
    fi
    i=$((i+1))
    sleep 1
  done

  if [ "$HEALTH_OK" -ne 1 ]; then
    cat "$TMP_LOG" >&2 || true
    die "La API temporal no respondió correctamente"
  fi

  log "Health CP1:"
  .venv/bin/python -m json.tool </tmp/vici-users-health.json || cat /tmp/vici-users-health.json

  .venv/bin/python - <<'PY'
import json
p='/tmp/vici-users-health.json'
with open(p) as fh:
    h=json.load(fh)
assert h.get('db_ok') is True, 'db_ok no es true'
assert h.get('db_host') == '172.20.20.198', 'db_host inesperado'
assert h.get('db_node') == 'vici222', 'db_node inesperado: %r' % (h.get('db_node'),)
assert h.get('db_name') == 'asterisk', 'db_name inesperado'
assert h.get('create_enabled') is False, 'CREATE debe permanecer deshabilitado en CP1'
assert h.get('extension_ranges_ok') is True, 'Rangos de extensiones inválidos'
assert h.get('extension_ranges_count') == 18, 'Se esperaban 18 bloques de extensiones'
assert h.get('inventory_db_ok') is True, 'Inventario local no disponible'
print('Health validado: vici97 -> vici222/asterisk, 18 rangos, inventario OK, CREATE=false')
PY

  log "Probando lectura de User Groups"
  curl -fsS "http://127.0.0.1:${PORT}/api/groups" >/tmp/vici-users-groups.json
  .venv/bin/python - <<'PY'
import json
with open('/tmp/vici-users-groups.json') as fh:
    d=json.load(fh)
g=d.get('groups', [])
assert g, 'No se recibieron User Groups'
print('User Groups visibles:', len(g))
print('Muestra:', ', '.join(str(x.get('user_group')) for x in g[:5]))
PY
  ok "CP1 de lectura validado"

  kill "$TEST_PID" 2>/dev/null || true
  wait "$TEST_PID" 2>/dev/null || true
  unset TEST_PID
else
  log "Validando health del servicio existente"
  curl -fsS "http://127.0.0.1:${PORT}/api/health" | .venv/bin/python -m json.tool
fi

if [ "$INSTALL_SERVICE" -eq 1 ]; then
  [ "$(id -u)" -eq 0 ] || die "--install-service requiere root"
  [ -f deploy/vici-users.service ] || die "No existe deploy/vici-users.service"

  TS="$(date +%Y%m%d_%H%M%S)"
  if [ -f "$SERVICE_DST" ]; then
    cp -a "$SERVICE_DST" "${SERVICE_DST}.bak_${TS}"
    warn "Backup unit: ${SERVICE_DST}.bak_${TS}"
  fi
  if [ -f "$ENV_DST" ]; then
    cp -a "$ENV_DST" "${ENV_DST}.bak_${TS}"
    warn "Backup env: ${ENV_DST}.bak_${TS}"
  fi

  install -m 0644 deploy/vici-users.service "$SERVICE_DST"
  cat > "$ENV_DST" <<EOF
ASTGUI_CONF=${ASTGUI_CONF}
VICI_DB_HOST=${DB_HOST}
VICI_DB_EXPECTED_HOST=${DB_HOST}
VICI_DB_NAME=${DB_NAME}
VICI_USERS_ENABLE_CREATE=false
VICI_USERS_USERNAME_MAX_LENGTH=20
VICI_USERS_INVENTORY_DB=${INVENTORY_DB}
EOF
  install -d -m 0700 "$INVENTORY_DIR"
  chmod 0644 "$ENV_DST"
  systemctl daemon-reload
  ok "Servicio instalado. CREATE permanece en false."

  if [ "$START_SERVICE" -eq 1 ]; then
    systemctl enable --now "$SERVICE_NAME"
    sleep 1
    systemctl --no-pager --full status "$SERVICE_NAME" || true
    curl -fsS "http://127.0.0.1:${PORT}/api/health" | .venv/bin/python -m json.tool
    ok "Servicio habilitado e iniciado"
  else
    log "Para iniciar después: systemctl enable --now ${SERVICE_NAME}"
  fi
fi

cat <<EOF

============================================================
 Vici-Users bootstrap completado
============================================================
 Host app : ${CURRENT_HOST}
 DB       : vici222 (${DB_HOST}) / ${DB_NAME}
 Puerto   : 127.0.0.1:${PORT}
 CREATE   : false
 Venv     : ${APP_DIR}/.venv

Siguiente validación manual:
  cd ${APP_DIR}
  .venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port ${PORT}

O, si ya instalaste systemd:
  systemctl status ${SERVICE_NAME}
============================================================
EOF
