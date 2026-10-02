const express = require('express');
const crypto = require('crypto');
const dotenv = require('dotenv');
const { Pool } = require('pg');

// Asthi Control Server 1.0.0
// This service handles authentication/licensing only.
// It does NOT send WhatsApp messages and does NOT use the WhatsApp API.

dotenv.config();

const app = express();
const port = Number(process.env.PORT || 8787);
const sessionSecret = process.env.SESSION_SECRET || 'CHANGE_ME';
const corsOrigin = process.env.CORS_ORIGIN || '*';

if (sessionSecret === 'CHANGE_ME' || sessionSecret.length < 24) {
  console.warn('ADVERTENCIA: configura SESSION_SECRET con una cadena aleatoria de al menos 24 caracteres.');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined
});

app.disable('x-powered-by');
app.use(express.json({ limit: '64kb' }));
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', corsOrigin);
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Installation-Id');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

function uuid() { return crypto.randomUUID(); }
function normalize(text = '') {
  return String(text).normalize('NFD').replace(/[\u0300-\u036f]/g, '').trim().replace(/\s+/g, ' ').toLowerCase();
}
function displayName(firstName, firstSurname) { return `${firstName} ${firstSurname}`.trim(); }
function normalizeName(firstName, firstSurname) { return normalize(displayName(firstName, firstSurname)); }
function sha256(value) { return crypto.createHash('sha256').update(String(value)).digest('hex'); }
function randomToken() { return crypto.randomBytes(48).toString('base64url'); }
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return `scrypt:${salt}:${derived}`;
}
function verifyPassword(password, stored) {
  const [scheme, salt, expected] = String(stored || '').split(':');
  if (scheme !== 'scrypt' || !salt || !expected) return false;
  const actual = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
}
function requireBody(body, fields) {
  for (const field of fields) {
    if (!String(body?.[field] ?? '').trim()) return `Falta el campo ${field}.`;
  }
  return null;
}

async function query(text, params = []) {
  return pool.query(text, params);
}

async function initDatabase() {
  if (!process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL no esta configurado.');
  }
  const schema = require('fs').readFileSync(require('path').join(__dirname, 'schema.sql'), 'utf8');
  await query(schema);

  const labels = ['Clave 1', 'Clave 2', 'Clave 3', 'Clave 4', 'Clave 5 (configurable)'];
  for (let i = 1; i <= 5; i++) {
    await query(`INSERT INTO key_slots (slot, label) VALUES ($1, $2) ON CONFLICT (slot) DO NOTHING`, [i, labels[i - 1]]);
  }

  const adminEmail = normalize(process.env.ADMIN_EMAIL || '');
  const adminPassword = String(process.env.ADMIN_PASSWORD || '');
  if (adminEmail && adminPassword) {
    const existing = await query('SELECT id FROM admins WHERE email = $1 LIMIT 1', [adminEmail]);
    if (!existing.rowCount) {
      await query('INSERT INTO admins (id, email, password_hash) VALUES ($1, $2, $3)', [uuid(), adminEmail, hashPassword(adminPassword)]);
      console.log(`Administrador inicial creado: ${adminEmail}`);
    }
  }
}

async function createSession({ userId = null, adminId = null }) {
  const token = randomToken();
  const tokenHash = sha256(token);
  const id = uuid();
  await query(`INSERT INTO sessions (id, user_id, admin_id, token_hash, expires_at) VALUES ($1,$2,$3,$4,NOW() + INTERVAL '30 days')`, [id, userId, adminId, tokenHash]);
  return token;
}

async function authSession(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ ok: false, error: 'No autorizado.' });
  const tokenHash = sha256(auth.slice(7));
  const result = await query(`SELECT s.*, u.active AS user_active, a.active AS admin_active
    FROM sessions s
    LEFT JOIN users u ON u.id = s.user_id
    LEFT JOIN admins a ON a.id = s.admin_id
    WHERE s.token_hash = $1 AND s.expires_at > NOW() LIMIT 1`, [tokenHash]);
  if (!result.rowCount) return res.status(401).json({ ok: false, error: 'Sesión no válida o vencida.' });
  const session = result.rows[0];
  if (session.user_id && !session.user_active) return res.status(403).json({ ok: false, code: 'USER_INACTIVE', error: 'Usuario inactivo. Comunícate con el administrador.' });
  if (session.admin_id && !session.admin_active) return res.status(403).json({ ok: false, code: 'ADMIN_INACTIVE', error: 'Acceso administrativo inactivo.' });
  await query('UPDATE sessions SET last_seen_at = NOW() WHERE id = $1', [session.id]);
  req.session = session;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session?.admin_id) return res.status(403).json({ ok: false, error: 'Se requiere acceso administrativo.' });
  next();
}

app.get('/salud', async (req, res) => {
  try {
    await query('SELECT 1');
    res.json({ ok: true, service: 'asthi-control', version: '1.0.0' });
  } catch (error) {
    res.status(503).json({ ok: false, service: 'asthi-control', error: 'Base de datos no disponible.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const firstName = String(req.body?.firstName || '').trim();
    const firstSurname = String(req.body?.firstSurname || '').trim();
    const password = String(req.body?.password || '');
    const installationId = String(req.body?.installationId || '').trim();
    if (!firstName || !firstSurname || !password) return res.status(400).json({ ok: false, error: 'Completa tus datos de acceso.' });

    const name = normalizeName(firstName, firstSurname);
    const userResult = await query('SELECT * FROM users WHERE normalized_name = $1 LIMIT 1', [name]);
    if (!userResult.rowCount) return res.status(401).json({ ok: false, error: 'Los datos ingresados no son válidos.' });
    const user = userResult.rows[0];
    const slotResult = await query('SELECT key_hash FROM key_slots WHERE slot = $1 AND active = TRUE LIMIT 1', [user.key_slot]);
    const valid = user.active && slotResult.rowCount && slotResult.rows[0].key_hash && verifyPassword(password, slotResult.rows[0].key_hash);
    if (!valid) {
      if (!user.active) return res.status(403).json({ ok: false, code: 'USER_INACTIVE', error: 'Usuario inactivo. Comunícate con el administrador.' });
      return res.status(401).json({ ok: false, error: 'Los datos ingresados no son válidos.' });
    }

    const token = await createSession({ userId: user.id });
    await query('UPDATE users SET last_login_at = NOW(), last_seen_at = NOW(), updated_at = NOW() WHERE id = $1', [user.id]);
    if (installationId) {
      await query(`INSERT INTO installations (id,user_id,installation_id,extension_version,chrome_version,platform)
        VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (installation_id) DO UPDATE SET user_id=EXCLUDED.user_id, extension_version=EXCLUDED.extension_version, chrome_version=EXCLUDED.chrome_version, platform=EXCLUDED.platform, active=TRUE, last_seen_at=NOW()`,
        [uuid(), user.id, installationId, String(req.body?.extensionVersion || ''), String(req.body?.chromeVersion || ''), String(req.body?.platform || '')]);
    }
    res.json({ ok: true, token, user: { id: user.id, name: displayName(user.first_name, user.first_surname), active: user.active } });
  } catch (error) {
    console.error('login error', error);
    res.status(500).json({ ok: false, error: 'No se pudo completar el acceso.' });
  }
});

app.post('/api/auth/validate', authSession, async (req, res) => {
  res.json({ ok: true, active: true, userId: req.session.user_id || null, admin: Boolean(req.session.admin_id) });
});

app.post('/api/auth/logout', authSession, async (req, res) => {
  await query('DELETE FROM sessions WHERE id = $1', [req.session.id]);
  res.json({ ok: true });
});

app.post('/api/admin/login', async (req, res) => {
  try {
    const email = normalize(req.body?.email || '');
    const password = String(req.body?.password || '');
    const result = await query('SELECT * FROM admins WHERE email = $1 LIMIT 1', [email]);
    if (!result.rowCount || !result.rows[0].active || !verifyPassword(password, result.rows[0].password_hash)) {
      return res.status(401).json({ ok: false, error: 'Los datos administrativos no son válidos.' });
    }
    const token = await createSession({ adminId: result.rows[0].id });
    res.json({ ok: true, token, admin: { id: result.rows[0].id, email: result.rows[0].email } });
  } catch (error) {
    console.error('admin login error', error);
    res.status(500).json({ ok: false, error: 'No se pudo completar el acceso administrativo.' });
  }
});

app.get('/api/admin/dashboard', authSession, requireAdmin, async (req, res) => {
  const [users, installations] = await Promise.all([
    query('SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE active)::int AS active, COUNT(*) FILTER (WHERE NOT active)::int AS inactive FROM users'),
    query('SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE active)::int AS active FROM installations')
  ]);
  res.json({ ok: true, users: users.rows[0], installations: installations.rows[0] });
});

app.get('/api/admin/users', authSession, requireAdmin, async (req, res) => {
  const result = await query(`SELECT id, first_name, first_surname, key_slot, active, created_at, updated_at, last_login_at, last_seen_at
    FROM users ORDER BY first_surname, first_name`);
  res.json({ ok: true, users: result.rows.map(u => ({ ...u, name: displayName(u.first_name, u.first_surname), key: `•••••••• (${u.key_slot})` })) });
});

app.get('/api/admin/keys', authSession, requireAdmin, async (req, res) => {
  const result = await query('SELECT slot, label, active, (key_hash IS NOT NULL) AS configured FROM key_slots ORDER BY slot');
  res.json({ ok: true, keys: result.rows });
});

app.post('/api/admin/keys/:slot', authSession, requireAdmin, async (req, res) => {
  const slot = Number(req.params.slot);
  const key = String(req.body?.key || '');
  if (!Number.isInteger(slot) || slot < 1 || slot > 5 || !key) return res.status(400).json({ ok: false, error: 'Clave no válida.' });
  await query('UPDATE key_slots SET key_hash=$1, active=TRUE, updated_at=NOW() WHERE slot=$2', [hashPassword(key), slot]);
  res.json({ ok: true, message: 'Clave actualizada.' });
});

app.patch('/api/admin/keys/:slot', authSession, requireAdmin, async (req, res) => {
  const slot = Number(req.params.slot);
  const active = Boolean(req.body?.active);
  if (!Number.isInteger(slot) || slot < 1 || slot > 5) return res.status(400).json({ ok: false, error: 'Slot no válido.' });
  await query('UPDATE key_slots SET active=$1, updated_at=NOW() WHERE slot=$2', [active, slot]);
  res.json({ ok: true });
});

app.post('/api/admin/users', authSession, requireAdmin, async (req, res) => {
  try {
    const firstName = String(req.body?.firstName || '').trim();
    const firstSurname = String(req.body?.firstSurname || '').trim();
    const keySlot = Number(req.body?.keySlot);
    const active = req.body?.active !== false;
    const error = requireBody({ firstName, firstSurname }, ['firstName', 'firstSurname']);
    if (error || !Number.isInteger(keySlot) || keySlot < 1 || keySlot > 5) return res.status(400).json({ ok: false, error: error || 'Slot de clave no válido.' });
    const normalizedName = normalizeName(firstName, firstSurname);
    const duplicate = await query('SELECT id FROM users WHERE normalized_name=$1 LIMIT 1', [normalizedName]);
    if (duplicate.rowCount) return res.status(409).json({ ok: false, error: 'Ese usuario ya existe.' });
    const slot = await query('SELECT key_hash, active FROM key_slots WHERE slot=$1', [keySlot]);
    if (!slot.rowCount || !slot.rows[0].active || !slot.rows[0].key_hash) return res.status(409).json({ ok: false, error: 'La clave seleccionada no está configurada o está inactiva.' });
    const id = uuid();
    await query(`INSERT INTO users (id,first_name,first_surname,normalized_name,key_slot,active) VALUES ($1,$2,$3,$4,$5,$6)`, [id, firstName, firstSurname, normalizedName, keySlot, active]);
    res.status(201).json({ ok: true, user: { id, name: displayName(firstName, firstSurname), keySlot, active } });
  } catch (error) {
    console.error('create user error', error);
    res.status(500).json({ ok: false, error: 'No se pudo crear el usuario.' });
  }
});

app.patch('/api/admin/users/:id', authSession, requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const existing = await query('SELECT * FROM users WHERE id=$1 LIMIT 1', [id]);
    if (!existing.rowCount) return res.status(404).json({ ok: false, error: 'Usuario no encontrado.' });
    const current = existing.rows[0];
    const firstName = String(req.body?.firstName ?? current.first_name).trim();
    const firstSurname = String(req.body?.firstSurname ?? current.first_surname).trim();
    const keySlot = req.body?.keySlot === undefined ? current.key_slot : Number(req.body.keySlot);
    const active = req.body?.active === undefined ? current.active : Boolean(req.body.active);
    if (!firstName || !firstSurname || !Number.isInteger(keySlot) || keySlot < 1 || keySlot > 5) return res.status(400).json({ ok: false, error: 'Datos de usuario no válidos.' });
    const normalizedName = normalizeName(firstName, firstSurname);
    const duplicate = await query('SELECT id FROM users WHERE normalized_name=$1 AND id<>$2 LIMIT 1', [normalizedName, id]);
    if (duplicate.rowCount) return res.status(409).json({ ok: false, error: 'Ese nombre ya pertenece a otro usuario.' });
    const slot = await query('SELECT key_hash, active FROM key_slots WHERE slot=$1', [keySlot]);
    if (!slot.rowCount || !slot.rows[0].active || !slot.rows[0].key_hash) return res.status(409).json({ ok: false, error: 'La clave seleccionada no está configurada o está inactiva.' });
    await query(`UPDATE users SET first_name=$1, first_surname=$2, normalized_name=$3, key_slot=$4, active=$5, updated_at=NOW() WHERE id=$6`, [firstName, firstSurname, normalizedName, keySlot, active, id]);
    if (!active) await query('DELETE FROM sessions WHERE user_id=$1', [id]);
    res.json({ ok: true });
  } catch (error) {
    console.error('update user error', error);
    res.status(500).json({ ok: false, error: 'No se pudo actualizar el usuario.' });
  }
});

app.delete('/api/admin/users/:id', authSession, requireAdmin, async (req, res) => {
  await query('DELETE FROM users WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

app.post('/api/client/heartbeat', authSession, async (req, res) => {
  if (!req.session.user_id) return res.status(403).json({ ok: false, error: 'Solo usuarios de Asthi Sender.' });
  const installationId = String(req.body?.installationId || '').trim();
  if (!installationId) return res.status(400).json({ ok: false, error: 'Falta installationId.' });
  await query(`UPDATE installations SET last_seen_at=NOW(), extension_version=$1, chrome_version=$2, platform=$3 WHERE installation_id=$4 AND user_id=$5`, [String(req.body?.extensionVersion || ''), String(req.body?.chromeVersion || ''), String(req.body?.platform || ''), installationId, req.session.user_id]);
  await query('UPDATE users SET last_seen_at=NOW() WHERE id=$1', [req.session.user_id]);
  res.json({ ok: true, active: true });
});

app.use(express.static(require('path').join(__dirname, 'public')));
app.get('/', (req, res) => res.sendFile(require('path').join(__dirname, 'public', 'admin.html')));

initDatabase().then(() => {
  app.listen(port, () => console.log(`Asthi Control Server 1.0.0 escuchando en http://localhost:${port}`));
}).catch(error => {
  console.error('No se pudo iniciar Asthi Control Server:', error.message);
  process.exit(1);
});
