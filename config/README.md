# Configuración de User Groups y extensiones

Vici-Users usa exactamente **un usuario plantilla por `user_group`** y un bloque
de extensiones para los grupos habilitados para alta.

## Plantillas

La configuración productiva de plantillas no se guarda en GitHub. En `vici97`
debe existir:

```text
/etc/vici-users/group_templates.json
```

Formato:

```json
{
  "GRUPO_A": "BASE_A",
  "GRUPO_B": "BASE_B"
}
```

Reglas:

- el usuario base debe existir en `vicidial_users`;
- puede estar `active='N'` porque es una plantilla técnica;
- debe pertenecer al mismo `user_group` configurado;
- el frontend no puede sustituirlo por otro usuario;
- el password de los usuarios nuevos no se toma de esta plantilla.

## Passwords default

Los passwords default permanecen únicamente en:

```text
/etc/vici-users/group_defaults.json
```

No deben publicarse en GitHub ni devolverse al navegador.

## Bloques de extensiones

`config/extension_ranges.json` define los grupos habilitados para el flujo de
alta y su bloque máximo de extensiones. Cada bloque puede contener como máximo
50 posiciones.

Un grupo administrado que no aparezca en ese archivo continúa existiendo para
consulta/configuración, pero el backend rechaza su alta automática.

Formato:

```json
{
  "GRUPO_A": {
    "start": 81001,
    "end": 81050
  }
}
```

El archivo sólo define el bloque permitido. Todavía no implica que una posición
esté libre, ocupada o reciclable; esa validación corresponde al inventario y al
motor de provisión.


## Inventario local de extensiones

El estado administrado por el portal se guarda fuera de VICIdial, por defecto en:

```text
/var/lib/vici-users/extension_inventory.db
```

Estados previstos:

- `UNCREATED`: número dentro del bloque que todavía no existe en `phones`;
- `LEGACY`: existe en `phones`, pero el portal aún no administra su ciclo de vida;
- `FREE`: extensión liberada explícitamente por un cambio gestionado por el portal;
- `RESERVED`: reservada temporalmente durante una operación;
- `IN_USE`: asignada por el portal;
- `ERROR`: estado inconsistente que requiere revisión.

Por seguridad, una extensión `LEGACY` nunca se considera reciclable automáticamente.
El pool reutilizable comienza únicamente con extensiones que el propio portal haya
marcado `FREE` después de completar correctamente una reasignación.

El endpoint de inventario público devuelve sólo un resumen y no publica IPs de
dialers ni el detalle completo de posiciones.


## Topología efectiva de provisión

`config/cluster_nodes.json` define qué dialers forman parte de una creación de
extensión. Un nodo con `enabled=false` sigue perteneciendo al cluster, pero no
es obligatorio para considerar completa una provisión nueva.

Actualmente EHECTO trabaja con 4 nodos obligatorios y 1 nodo temporalmente
excluido por problemas de registro. Las filas ya existentes en un nodo
deshabilitado siguen siendo visibles al inventario y nunca hacen que una
extensión pase a `UNCREATED`.

Cuando el nodo excluido vuelva a estar operativo, basta con cambiar su bandera a
`enabled=true`; a partir de ese momento la validación de topología exigirá de
nuevo 5/5 nodos. Antes de habilitarlo para nuevas altas debe ejecutarse un fix
para completar las extensiones que hayan sido creadas durante el periodo 4/4.


## Regla canónica de identidad para nuevas extensiones

Las extensiones históricas pueden tener sufijos y prefijos diferentes porque
fueron creadas con distintos órdenes de bulk. El portal no intenta normalizar
ni reescribir esos registros legacy.

Para nuevas provisiones se usa `identity_policy=canonical-v1`:

- 172.20.20.233 → sufijo `a`, sin prefijo de dialplan;
- 172.20.21.90 → sufijo `b`, prefijo `1`;
- 172.20.21.96 → sufijo `c`, prefijo `2`;
- 172.20.20.110 → sufijo `d`, prefijo `3`;
- 172.20.21.94 → sufijo `e`, prefijo `4`, temporalmente deshabilitado.

Ejemplo para extensión 95217:

```text
172.20.20.233 -> login 95217a -> dialplan 95217
172.20.21.90  -> login 95217b -> dialplan 195217
172.20.21.96  -> login 95217c -> dialplan 295217
172.20.20.110 -> login 95217d -> dialplan 395217
172.20.21.94  -> login 95217e -> dialplan 495217 (no se crea mientras esté disabled)
```

Esta regla aplica sólo a altas nuevas administradas por Vici-Users.


## Dry-run de provisión de phones

Antes de cualquier escritura, el backend puede construir un plan de provisión
para una extensión concreta. El dry-run:

- valida que la extensión esté dentro del bloque del User Group;
- confirma que la extensión objetivo no exista ya en `phones`;
- calcula `login` y `dialplan_number` con la política canónica;
- selecciona una extensión plantilla activa del mismo User Group y del mismo nodo;
- valida `template_id` y que exista `conf_secret` sin devolver su valor;
- busca colisiones de login/dialplan;
- exige plantilla válida en los 4 nodos habilitados;
- no ejecuta INSERT, UPDATE ni DELETE.

Como `phones` y `vicidial_users` son MyISAM, el futuro motor de escritura no
puede depender de ROLLBACK transaccional. El diseño usa compensación explícita
y validación posterior.


## Dry-run exacto de escritura usuario + extensión

El endpoint `POST /api/provisioning/write-plan` genera el plan exacto de una
alta sin ejecutar escrituras. Usa el mismo allowlist funcional de usuarios que
`configure-base-users.sh` y construye, por cada nodo habilitado, un
`INSERT ... SELECT` explícito sobre `phones`.

El plan:

- valida que el username no exista;
- valida de nuevo extensión, login y dialplan;
- usa el `BASE_*` del User Group como fuente del usuario;
- usa una extensión activa del mismo grupo/nodo como fuente de `phones`;
- crea conceptualmente los phones con `active=N`;
- copia `conf_secret` desde la plantilla sin devolver su valor;
- sustituye extension, dialplan_number, voicemail_id, login, pass, user_group y active;
- detecta referencias no mapeadas a la extensión fuente en otros campos y bloquea el plan;
- describe la activación final y el rollback compensatorio requerido por MyISAM;
- nunca devuelve el password default del grupo y nunca ejecuta INSERT/UPDATE/DELETE.

`VICI_USERS_ENABLE_CREATE=false` debe permanecer así hasta que este plan sea
validado y se implementen autenticación, auditoría e idempotencia para la
escritura real.


### Mapeo de fullname en phones

El dry-run detectó que `phones.fullname` contiene la extensión fuente. Para
altas nuevas, el portal conserva el formato exacto de la plantilla del mismo
nodo y sustituye únicamente la extensión fuente por la extensión destino.

Ejemplo conceptual:

```text
fullname fuente:  <formato que contiene 95201>
fullname destino: <mismo formato con 95217>
```

`fullname` pasa a formar parte del conjunto explícito de campos de identidad
del teléfono y deja de copiarse sin transformación.


### Estado operativo limpio para phones nuevos

El análisis de extensiones sanas confirmó que algunos campos reflejan estado
operativo y no deben heredarse desde la extensión plantilla.

Para altas nuevas el plan inicializa explícitamente:

```text
status         = ACTIVE
active         = N            # hasta validar el alta completa
phone_ip       = NULL
computer_ip    = NULL
messages       = 0
old_messages   = 0
login_user     = NULL
login_pass     = NULL
login_campaign = NULL
peer_status    = UNKNOWN
ping_time      = NULL
```

La configuración funcional (WebRTC, template_id, conf_secret, contextos,
codecs y demás campos no dinámicos) se sigue clonando desde la plantilla del
mismo nodo.


## Ejecutor real de provisión (cerrado por defecto)

El backend ya contiene un ejecutor real para una alta individual
usuario + extensión, pero permanece bloqueado por tres barreras:

```text
VICI_USERS_ENABLE_CREATE=false
VICI_USERS_WRITE_EXECUTOR_ENABLED=false
/etc/vici-users/write_token   (fuera de GitHub)
```

La ruta de ejecución es `POST /api/provisioning/execute`. Aunque el código de
escritura exista, no debe habilitarse todavía desde el frontend público.

El ejecutor usa:

- `idempotency_key` obligatorio para impedir reintentos duplicados;
- reserva SQLite con `BEGIN IMMEDIATE`;
- journal local `provisioning_operations`;
- phones creados primero con `active=N`;
- validación exacta de los 4 nodos;
- usuario creado con `active=N`;
- activación sólo después de validar ambos lados;
- inventario final `IN_USE`;
- compensación explícita de usuario y phones si falla una operación MyISAM.

La reutilización de extensiones `FREE` queda intencionalmente bloqueada en
esta primera versión del ejecutor. Sólo se permite el camino `UNCREATED`
cuando llegue el momento de habilitar escritura.

El token de escritura es un candado operativo temporal para pruebas locales; no
debe incrustarse en JavaScript/GitHub Pages. La autenticación de usuario final
del portal debe resolverse antes de habilitar creación desde navegador.


### Replay idempotente después de SUCCESS

El ejecutor consulta `provisioning_operations` por `idempotency_key` antes
de regenerar el write-plan. Si la clave ya terminó en `SUCCESS` y el payload
coincide exactamente, devuelve el resultado guardado sin volver a evaluar la
disponibilidad del usuario/extensión y sin ejecutar nuevas escrituras.

Esto cubre reintentos causados por timeouts o pérdida de respuesta después de
una operación ya completada. Una misma clave con payload diferente sigue
bloqueada con `IDEMPOTENCY_KEY_PAYLOAD_MISMATCH`.


## Autenticación de operadores del portal

La autenticación del portal vive completamente en `vici97`. No se guardan
usuarios, passwords ni tokens en GitHub Pages.

Configuración privada:

```text
/etc/vici-users/operators.json
```

El archivo debe ser `root:root 0600`. Los passwords se almacenan como
PBKDF2-HMAC-SHA256 con salt aleatorio y 260000 iteraciones.

El helper público:

```bash
./configure-operator.sh <usuario> [operator|admin]
```

solicita el password de forma interactiva y nunca lo imprime ni lo escribe en
el repositorio.

Endpoints de sesión:

```text
POST /api/auth/login
GET  /api/auth/me
POST /api/auth/logout
```

El login devuelve un token Bearer aleatorio. El backend guarda únicamente el
SHA-256 del token en SQLite. La sesión expira por defecto a los 1800 segundos y
puede configurarse con `VICI_USERS_AUTH_SESSION_TTL`.

Las sesiones y eventos de autenticación quedan en:

```text
auth_sessions
auth_audit
```

Después de 5 credenciales incorrectas para el mismo usuario dentro de 15
minutos, el login se bloquea temporalmente con HTTP 429.

La creación desde navegador sigue separada del ejecutor local. Mientras:

```text
VICI_USERS_PORTAL_WRITE_ENABLED=false
```

un operador puede autenticarse y validar la integración sin habilitar
escrituras desde GitHub Pages.


### API del portal protegida por sesión

Después de integrar la autenticación, las rutas operativas del portal requieren
un token Bearer válido. Permanecen públicas únicamente las rutas necesarias
para arrancar y autenticar:

```text
GET  /api/health
POST /api/auth/login
```

`/api/auth/me` y `/api/auth/logout` requieren sesión. También requieren
sesión los grupos, plantillas, inventario, auditoría, preview y dry-runs.

Los endpoints de diagnóstico detallado de usuarios requieren rol `admin`.
Las funciones normales de consulta y preview aceptan `operator` o `admin`.

El frontend guarda el token exclusivamente en `sessionStorage`, por lo que
no persiste entre sesiones completas del navegador. El password de operador
nunca se guarda en el navegador después del login.

La escritura del portal continúa bloqueada independientemente de la sesión
mientras `VICI_USERS_PORTAL_WRITE_ENABLED=false`.
