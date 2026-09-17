# Vici-Users — EHECTO

Herramienta para alta masiva de usuarios VICIdial usando un usuario existente como plantilla.

## Topología

```text
Navegador
   |
   v
Vici-Users / FastAPI
vici97 (marcador / orquestador)
   |
   | MySQL TCP 3306 - lectura controlada en CP1
   v
vici222 - 172.20.20.198
DataBase Only - DO NOT DELETE
   |
   +-- vicidial_users
   +-- vicidial_user_groups
   +-- resto de DB EHECTO
```

**vici97 NO es la base de datos.** El backend corre en vici97 y consulta la DB central en vici222.

## Runtime de vici97

El servidor usa Python 3.6.13. El proyecto está fijado a versiones compatibles y no requiere actualizar Python del sistema:

```text
FastAPI   0.83.0
Uvicorn   0.16.0
Pydantic  1.9.2
Starlette 0.19.1
PyMySQL   1.0.2
```

No se modifica `/usr/bin/python3`, no se instala gcc/make y no se actualiza pip global.

## Regla de username EHECTO

1. Primera letra del apellido paterno + primer nombre.
2. Si existe, usar dos letras del apellido + primer nombre.
3. Continuar ampliando el apellido hasta encontrar un username libre.
4. El preview siempre consulta `vicidial_users` antes de proponer el resultado final.

Ejemplo:

```text
Juan Perez
PJUAN   -> existe
PEJUAN  -> disponible
```

## CP1 — modo seguro

CP1 es estrictamente de consulta y preview:

- `/api/health`
- `/api/groups`
- `/api/groups/{group}/users`
- `/api/users/{user}`
- `/api/users/preview`

`POST /api/users/create` permanece bloqueado mientras:

```text
VICI_USERS_ENABLE_CREATE=false
```

El backend fuerza el destino DB a `172.20.20.198` y rechaza otro host cuando `VICI_DB_EXPECTED_HOST` está configurado.

## Bootstrap

Todo el despliegue de CP1 queda concentrado en `bootstrap.sh`. El bootstrap es idempotente y valida antes de dejar el servicio disponible.

### Primera instalación

```bash
cd /opt
git clone https://github.com/TeamDirecto/Vici-Users.git vici-users
cd /opt/vici-users
bash bootstrap.sh
```

El modo por defecto:

- verifica que se ejecute en `vici97`;
- valida `/etc/astguiclient.conf` sin mostrar `VARDB_pass`;
- exige `VARDB_server=172.20.20.198` y `VARDB_database=asterisk`;
- crea `/opt/vici-users/.venv` usando el Python 3.6 existente;
- instala sólo las dependencias fijadas del proyecto;
- valida sintaxis e imports;
- levanta temporalmente Uvicorn en `127.0.0.1:8094`;
- comprueba `/api/health` y exige `db_node=vici222`, `db_name=asterisk`, `db_ok=true` y `create_enabled=false`;
- prueba lectura real de User Groups;
- detiene la instancia temporal al terminar.

No instala ni inicia systemd por defecto.

### Instalar el servicio después de validar CP1

```bash
cd /opt/vici-users
bash bootstrap.sh --install-service
```

Esto copia el unit a `/etc/systemd/system/vici-users.service`, genera `/etc/sysconfig/vici-users`, mantiene `CREATE=false` y deja backup timestamp de archivos previos si existían.

Para instalar y arrancar en una sola ejecución:

```bash
bash bootstrap.sh --start-service
```

El servicio escucha únicamente en:

```text
127.0.0.1:8094
```

La exposición web se hará después mediante el proxy/reverse proxy aprobado; CP1 no abre Uvicorn directamente a la red.

### Reejecución

El bootstrap puede volver a ejecutarse. Si `.venv` ya existe lo reutiliza y vuelve a validar dependencias/API/DB.

Si el entorno ya está preparado y sólo se quiere validar:

```bash
bash bootstrap.sh --skip-pip
```

## Recomendación de permisos CP1

Para máxima seguridad, crear posteriormente en vici222 un usuario MySQL exclusivo para Vici-Users con acceso únicamente desde la IP de vici97 y permisos `SELECT` solamente sobre las tablas requeridas. No reutilizar una cuenta administrativa para el servicio web.

Tablas mínimas actuales:

```text
asterisk.vicidial_users
asterisk.vicidial_user_groups
```

## CP2 — creación

La escritura no debe habilitarse hasta completar:

1. backup/snapshot lógico de los registros involucrados;
2. validación del esquema real de `vicidial_users` en EHECTO;
3. definición explícita de campos heredables y campos que nunca se copian;
4. prueba con un único usuario de laboratorio;
5. validación desde VICIdial Admin;
6. auditoría y rollback.

Para la creación base se priorizará `non_agent_api.php` cuando haya un nodo web VICIdial apropiado. La copia de atributos no expuestos por la API se tratará por separado con lista blanca de columnas; nunca se hará `INSERT ... SELECT *`.
