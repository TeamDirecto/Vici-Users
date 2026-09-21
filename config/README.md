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
