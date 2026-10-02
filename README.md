# Asthi Control Server v1.0.0

Servidor remoto de autenticación y control de usuarios/licencias para **Asthi Sender**.

## Objetivo

Este servicio controla únicamente:
- autenticación de usuarios;
- claves de acceso por slots (1 a 5);
- estado activo/inactivo;
- sesiones;
- instalaciones autorizadas y última conexión;
- panel administrativo.

**No envía mensajes de WhatsApp, no usa WhatsApp API y no reemplaza el motor de envío de Asthi Sender.**

## Arquitectura

`Panel administrador → Asthi Control Server → Asthi Sender instalado en cada computadora`

La extensión se conectará al servidor mediante HTTPS en producción. WhatsApp Web seguirá funcionando dentro de la extensión como hasta ahora.

## Requisitos

- Node.js 20+
- PostgreSQL 14+
- Una URL `DATABASE_URL`

## Instalación local

1. Copiar `.env.example` como `.env`.
2. Configurar `DATABASE_URL`, `ADMIN_EMAIL`, `ADMIN_PASSWORD` y `SESSION_SECRET`.
3. Ejecutar `npm install`.
4. Ejecutar `npm start`.
5. Abrir `http://localhost:8787`.
6. Salud: `http://localhost:8787/salud`.

La base de datos y los slots 1–5 se crean automáticamente al arrancar.

## Producción

El servidor está preparado para un despliegue Node + PostgreSQL (por ejemplo, un servicio de hosting que entregue `PORT` y `DATABASE_URL`). En producción usar HTTPS y un `SESSION_SECRET` aleatorio largo.

## Seguridad

- Las claves no se almacenan en texto plano: se almacenan con scrypt y salt.
- Las contraseñas administrativas también usan scrypt.
- Los tokens de sesión se almacenan en la base como SHA-256 del token.
- Las claves nunca se devuelven por la API de administración.
- Al desactivar un usuario, sus sesiones activas se eliminan.
- El panel muestra únicamente `•••••••• (slot)` para la clave asignada.

## Próximo paso: integración con Asthi Sender

La extensión v1.3.0 todavía usa su autenticación local. La siguiente fase conectará su pantalla de acceso a:
- `POST /api/auth/login`
- `POST /api/auth/validate`
- `POST /api/auth/logout`
- `POST /api/client/heartbeat`

La integración debe hacerse sin modificar el motor de envío, contactos, Excel/CSV, variables, mensajes, adjuntos, pausas, reintentos, historial ni reportes.

## Nota de diseño

El servidor es el punto de autoridad para saber si un usuario está activo. Por eso una persona puede conservar el ZIP instalado y aun así perder el acceso cuando el administrador la desactive.
