#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_HOST="vici97"
VHOST="/etc/apache2/vhosts.d/1111-default-ssl.conf"
API_FQDN="vicidial97.directo.com"
LOCAL_API="http://127.0.0.1:8094/api/"
PUBLIC_PATH="/vici-users-api/"
MARK_BEGIN="# BEGIN VICI-USERS-API"
MARK_END="# END VICI-USERS-API"

log(){ printf '\033[1;34m[PUBLIC]\033[0m %s\n' "$*"; }
ok(){ printf '\033[1;32m[OK]\033[0m %s\n' "$*"; }
warn(){ printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
die(){ printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Ejecuta como root"
[ "$(hostname -s 2>/dev/null || hostname)" = "$EXPECTED_HOST" ] || die "Bootstrap válido sólo para vici97"
[ -f "$VHOST" ] || die "No existe $VHOST"

log "Validando backend local"
curl -fsS http://127.0.0.1:8094/api/health >/tmp/vici-users-health-public.json || die "Vici-Users no responde en 127.0.0.1:8094"
python3 - <<'PY'
import json
with open('/tmp/vici-users-health-public.json') as fh:
    h=json.load(fh)
assert h.get('db_ok') is True, 'db_ok no es true'
assert h.get('db_node') == 'vici222', 'DB no es vici222'
assert h.get('db_name') == 'asterisk', 'DB no es asterisk'
assert h.get('create_enabled') is False, 'CREATE debe seguir false'
assert h.get('write_executor_enabled') is False, 'WRITE EXECUTOR debe seguir false'
print('Backend OK: vici97 -> vici222/asterisk, CREATE=false, EXECUTOR=false')
PY

log "Validando módulos Apache"
MODS="$(apachectl -M 2>/dev/null || true)"
printf '%s\n' "$MODS" | grep -q 'proxy_module' || die "mod_proxy no está cargado"
printf '%s\n' "$MODS" | grep -q 'proxy_http_module' || die "mod_proxy_http no está cargado"
ok "mod_proxy y mod_proxy_http disponibles"

if grep -Fq "$MARK_BEGIN" "$VHOST"; then
  ok "Bloque Vici-Users ya existe en $VHOST; no se duplica"
else
  TS="$(date +%Y%m%d_%H%M%S)"
  BACKUP="${VHOST}.bak-vici-users-${TS}"
  cp -a "$VHOST" "$BACKUP"
  log "Backup: $BACKUP"

  TMP="$(mktemp)"
  awk -v begin="$MARK_BEGIN" -v end="$MARK_END" -v localapi="$LOCAL_API" -v publicpath="$PUBLIC_PATH" '
    /<\/VirtualHost>/ && !done {
      print ""
      print "    " begin
      print "    ProxyPreserveHost On"
      print "    ProxyPass        " publicpath " " localapi " retry=0 timeout=15"
      print "    ProxyPassReverse " publicpath " " localapi
      print "    " end
      print ""
      done=1
    }
    { print }
    END { if (!done) exit 42 }
  ' "$VHOST" > "$TMP" || {
    rc=$?
    rm -f "$TMP"
    die "No fue posible insertar el bloque Apache (rc=$rc)"
  }
  cat "$TMP" > "$VHOST"
  rm -f "$TMP"

  if ! apachectl configtest; then
    warn "configtest falló; restaurando $BACKUP"
    cp -a "$BACKUP" "$VHOST"
    apachectl configtest || true
    die "Cambio revertido"
  fi
  ok "Apache configtest OK"

  if ! systemctl reload apache2; then
    warn "reload falló; restaurando $BACKUP"
    cp -a "$BACKUP" "$VHOST"
    apachectl configtest || true
    systemctl reload apache2 || true
    die "Cambio revertido"
  fi
  ok "Apache recargado"
fi

log "Probando endpoint público localmente por HTTPS"
if curl -fsS "https://${API_FQDN}${PUBLIC_PATH}health" >/tmp/vici-users-public-health.json; then
  python3 -m json.tool </tmp/vici-users-public-health.json
  ok "Bridge HTTPS operativo: https://${API_FQDN}${PUBLIC_PATH}health"
else
  warn "Apache quedó configurado, pero curl HTTPS no pudo validar el FQDN desde vici97. Revisa DNS/certificado/ruta externa."
fi

cat <<EOF

============================================================
 Vici-Users public bridge preparado
============================================================
 Frontend Pages : https://teamdirecto.github.io/Vici-Users/
 API pública    : https://${API_FQDN}${PUBLIC_PATH}
 API local      : ${LOCAL_API}
 DB             : vici222 / asterisk
 CREATE         : false
 WRITE EXECUTOR  : false
============================================================
EOF
