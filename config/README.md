# Plantillas por User Group

Vici-Users usa exactamente **un usuario plantilla por `user_group`**.

La configuración productiva no se guarda en GitHub. En `vici97` debe existir:

```text
/etc/vici-users/group_templates.json
```

Formato:

```json
{
  "GRUPO_A": "USUARIO_BASE_A",
  "GRUPO_B": "USUARIO_BASE_B"
}
```

Reglas:

- el usuario base debe existir en `vicidial_users`;
- debe estar `active='Y'`;
- debe pertenecer al mismo `user_group` configurado;
- el frontend no puede sustituirlo por otro usuario;
- el password de los usuarios nuevos no se toma de esta plantilla y no se almacena aquí.

`config/group_templates.example.json` se mantiene vacío intencionalmente para no publicar nombres internos de usuarios/grupos en el repositorio público.
