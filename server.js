const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const client = require('prom-client');

const app = express();
app.use(express.json());

const pool = new Pool({
  host: process.env.DB_HOST || 'postgres',
  port: 5432,
  user: process.env.POSTGRES_USER,
  password: process.env.POSTGRES_PASSWORD,
  database: process.env.POSTGRES_DB,
});

client.collectDefaultMetrics();
const httpRequests = new client.Counter({
  name: 'http_requests_total',
  help: 'Total de peticiones HTTP',
  labelNames: ['method', 'route', 'status'],
});
const loginAttempts = new client.Counter({
  name: 'login_attempts_total',
  help: 'Intentos de login por resultado',
  labelNames: ['result'],
});

app.use((req, res, next) => {
  res.on('finish', () => {
    httpRequests.inc({ method: req.method, route: req.path, status: res.statusCode });
  });
  next();
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok' });
  } catch (e) {
    res.status(503).json({ status: 'db_error' });
  }
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username y password requeridos' });
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password_hash) VALUES ($1, $2)', [username, hash]);
    res.status(201).json({ message: 'usuario creado' });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'el usuario ya existe' });
    console.error(e);
    res.status(500).json({ error: 'error interno' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username y password requeridos' });
  try {
    const r = await pool.query('SELECT password_hash FROM users WHERE username = $1', [username]);
    const ok = r.rows.length > 0 && (await bcrypt.compare(password, r.rows[0].password_hash));
    loginAttempts.inc({ result: ok ? 'success' : 'failure' });
    if (!ok) return res.status(401).json({ error: 'credenciales inválidas' });
    res.json({ message: 'login exitoso' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'error interno' });
  }
});

app.get('/metrics', async (req, res) => {
  res.set('Content-Type', client.register.contentType);
  res.end(await client.register.metrics());
});

async function initDb(retries = 10) {
  for (let i = 0; i < retries; i++) {
    try {
      await pool.query(`CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT now()
      )`);
      console.log('DB lista');
      return;
    } catch (e) {
      console.log('Esperando DB...', e.message);
      await new Promise((r) => setTimeout(r, 3000));
    }
  }
  process.exit(1);
}

initDb().then(() => app.listen(3000, () => console.log('App escuchando en :3000')));
