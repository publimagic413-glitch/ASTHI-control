# TEST REPORT — Asthi Control Server v1.0.0

## Validaciones estáticas realizadas

- `node --check server.js` — PASS
- `node --check public/admin.js` — PASS
- JSON de `package.json` — PASS
- `schema.sql` presente — PASS
- `.env.example` presente — PASS
- No se incluyen claves reales ni contraseñas reales — PASS

## Pendiente de prueba de entorno

Requiere PostgreSQL real para probar:
- creación automática de tablas;
- creación del administrador inicial;
- login admin;
- creación de usuarios;
- activación/desactivación;
- login de usuario;
- revocación de sesión;
- heartbeat;
- persistencia de datos.

La integración con la extensión Asthi Sender v1.3.0 será una fase posterior. No se ha modificado el motor de envío en este paquete.
