const path = require('path');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const argon2 = require('argon2');
const { authenticator } = require('@otplib/preset-default');
const SQLiteStore = require('connect-sqlite3')(session);

const app = express();

// ---- Config ----
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev_change_me_in_env';
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data.db');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());

app.use(
  session({
    name: 'sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false, // set true behind HTTPS
      maxAge: 1000 * 60 * 60 * 2
    }
  })
);

const csrfProtection = csurf({ cookie: false });

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/login');
}

function escapeBasic(str) {
  return String(str || '').trim();
}

function validateRegistration(body) {
  const username = escapeBasic(body.username);
  const password = String(body.password || '');
  const confirmPassword = String(body.confirmPassword || '');

  const errors = [];
  if (username.length < 3 || username.length > 30) errors.push('Username must be 3-30 characters.');
  if (!/^([a-zA-Z0-9_]+)$/.test(username)) errors.push('Username may contain letters, numbers, and underscore only.');
  if (password.length < 10) errors.push('Password must be at least 10 characters.');
  if (password !== confirmPassword) errors.push('Passwords do not match.');

  return { username, password, errors };
}

function validateLogin(body) {
  const username = escapeBasic(body.username);
  const password = String(body.password || '');
  const errors = [];
  if (username.length < 3 || username.length > 30) errors.push('Invalid username.');
  if (!password) errors.push('Password is required.');
  return { username, password, errors };
}

async function main() {
  const db = await open({ filename: DB_PATH, driver: sqlite3.Database });

  await db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      twofa_enabled INTEGER NOT NULL DEFAULT 0,
      twofa_secret TEXT
    );
  `);

  app.locals.db = db;

  // ---- Routes ----
  app.get('/', (req, res) => {
    if (req.session.userId) return res.redirect('/dashboard');
    res.redirect('/login');
  });

  app.get('/register', csrfProtection, (req, res) => {
    res.render('register', { csrfToken: req.csrfToken(), error: null });
  });

  app.post('/register', csrfProtection, async (req, res) => {
    const { username, password, errors } = validateRegistration(req.body);
    if (errors.length) {
      return res.status(400).render('register', { csrfToken: req.csrfToken(), error: errors[0] });
    }

    try {
      const existing = await db.get('SELECT id FROM users WHERE username = ?', [username]);
      if (existing) {
        return res.status(400).render('register', { csrfToken: req.csrfToken(), error: 'Username already exists.' });
      }

      const passwordHash = await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 19456,
        timeCost: 2,
        parallelism: 1
      });

      await db.run(
        'INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, datetime("now"))',
        [username, passwordHash]
      );

      res.redirect('/login');
    } catch (e) {
      return res.status(500).render('register', { csrfToken: req.csrfToken(), error: 'Registration failed.' });
    }
  });

  app.get('/login', csrfProtection, (req, res) => {
    res.render('login', { csrfToken: req.csrfToken(), error: null });
  });

  app.post('/login', csrfProtection, async (req, res) => {
    const { username, password, errors } = validateLogin(req.body);
    if (errors.length) {
      return res.status(400).render('login', { csrfToken: req.csrfToken(), error: errors[0] });
    }

    const user = await db.get('SELECT id, password_hash, twofa_enabled FROM users WHERE username = ?', [username]);
    if (!user) return res.status(400).render('login', { csrfToken: req.csrfToken(), error: 'Invalid credentials.' });

    let ok = false;
    try {
      ok = await argon2.verify(user.password_hash, password);
    } catch {
      ok = false;
    }

    if (!ok) return res.status(400).render('login', { csrfToken: req.csrfToken(), error: 'Invalid credentials.' });

    if (user.twofa_enabled) {
      // Store pending login until 2FA verified
      req.session.pendingUserId = user.id;
      req.session.pending2fa = true;
      return res.redirect('/2fa');
    }

    req.session.userId = user.id;
    delete req.session.pendingUserId;
    delete req.session.pending2fa;
    res.redirect('/dashboard');
  });

  app.get('/2fa', csrfProtection, async (req, res) => {
    if (!req.session.pending2fa || !req.session.pendingUserId) return res.redirect('/login');

    const user = await db.get('SELECT username FROM users WHERE id = ?', [req.session.pendingUserId]);
    res.render('2fa', { csrfToken: req.csrfToken(), error: null, username: user?.username || '' });
  });

  app.post('/2fa', csrfProtection, async (req, res) => {
    if (!req.session.pending2fa || !req.session.pendingUserId) return res.redirect('/login');

    const code = String(req.body.code || '').trim();
    if (!/^\d{6}$/.test(code)) {
      return res.status(400).render('2fa', { csrfToken: req.csrfToken(), error: 'Enter a valid 6-digit code.', username: '' });
    }

    const user = await db.get('SELECT twofa_secret FROM users WHERE id = ?', [req.session.pendingUserId]);
    if (!user?.twofa_secret) return res.redirect('/login');

    const valid = authenticator.check(code, user.twofa_secret);
    if (!valid) {
      return res.status(400).render('2fa', { csrfToken: req.csrfToken(), error: 'Invalid code.', username: '' });
    }

    req.session.userId = req.session.pendingUserId;
    delete req.session.pendingUserId;
    delete req.session.pending2fa;
    res.redirect('/dashboard');
  });

  app.get('/dashboard', csrfProtection, requireAuth, async (req, res) => {
    const user = await db.get('SELECT id, username, twofa_enabled FROM users WHERE id = ?', [req.session.userId]);
    res.render('dashboard', { csrfToken: req.csrfToken(), user });
  });

  app.post('/logout', csrfProtection, (req, res) => {
    req.session.destroy(() => {
      res.clearCookie('sid');
      res.redirect('/login');
    });
  });

  // ---- 2FA Setup (optional) ----
  app.get('/2fa/setup', csrfProtection, requireAuth, async (req, res) => {
    const user = await db.get('SELECT id FROM users WHERE id = ?', [req.session.userId]);
    if (!user) return res.redirect('/login');

    // Create secret and show QR manually via otpauth URL
    const secret = authenticator.generateSecret();
    const issuer = 'Secure Login System';
    const otpauth = authenticator.keyuri(user.id.toString(), issuer, secret);

    await db.run('UPDATE users SET twofa_secret = ? WHERE id = ?', [secret, req.session.userId]);

    res.render('2fa_setup', { csrfToken: req.csrfToken(), otpauth, secret });
  });

  app.post('/2fa/enable', csrfProtection, requireAuth, async (req, res) => {
    const code = String(req.body.code || '').trim();
    if (!/^\d{6}$/.test(code)) {
      return res.status(400).render('2fa_setup', { csrfToken: req.csrfToken(), error: 'Enter a valid 6-digit code.', otpauth: null, secret: null });
    }

    const user = await db.get('SELECT twofa_secret FROM users WHERE id = ?', [req.session.userId]);
    if (!user?.twofa_secret) return res.redirect('/2fa/setup');

    const valid = authenticator.check(code, user.twofa_secret);
    if (!valid) {
      return res.status(400).render('2fa_setup', { csrfToken: req.csrfToken(), error: 'Invalid code.', otpauth: null, secret: null });
    }

    await db.run('UPDATE users SET twofa_enabled = 1 WHERE id = ?', [req.session.userId]);
    res.redirect('/dashboard');
  });

  app.listen(PORT, () => {
    console.log(`Secure Login System running on http://localhost:${PORT}`);
  });
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

