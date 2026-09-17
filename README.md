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

El servicio fuerza el destino de DB a `172.20.20.198` y el backend rechaza otro host cuando `VICI_DB_EXPECTED_HOST` está configurado.

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
2. validación de esquema real de `vicidial_users` en EHECTO;
3. definición explícita de campos heredables y campos que nunca se copian;
4. prueba con un único usuario de laboratorio;
5. validación desde VICIdial Admin;
6. auditoría y rollback.

Para la creación base de usuarios se priorizará la API oficial `non_agent_api.php` cuando haya un nodo web VICIdial apropiado. La copia de atributos que esa API no exponga se tratará por separado y con una lista blanca de columnas; no se hará `INSERT ... SELECT *`.

## Despliegue previsto en vici97

```bash
git clone https://github.com/TeamDirecto/Vici-Users.git /opt/vici-users
cd /opt/vici-users
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
cp deploy/vici-users.service /etc/systemd/system/vici-users.service
systemctl daemon-reload
systemctl enable --now vici-users
```

Validación:

```bash
curl -s http://127.0.0.1:8094/api/health
curl -s http://127.0.0.1:8094/api/groups
```

La respuesta de `health` debe indicar que la aplicación está en vici97 y que la DB accesible corresponde a vici222 / `172.20.20.198` antes de continuar.
