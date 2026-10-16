const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { DatabaseSync } = require('node:sqlite');
const QRCode = require('qrcode');
const ExcelJS = require('exceljs');
const multer = require('multer');
const { Client, LocalAuth } = require('whatsapp-web.js');

const PORT = process.env.PORT || 3000;
// Use an installed Chrome/Edge instead of Puppeteer's bundled Chromium
const BROWSER_PATH = process.env.CHROME_PATH || [
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
  'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
].find((p) => fs.existsSync(p));
const RATE_LIMIT_PER_MINUTE = 30; // website checks, per user (the page checks lists one number at a time)
const API_RATE_LIMIT_PER_MINUTE = 30; // API requests, per API key
const AUTH_RATE_LIMIT_PER_MINUTE = 10; // login/register attempts, per IP
const CHECK_MAX_NUMBERS = 50; // numbers per /check request (~2 min at the pacing below)
// Sending: small batches, extra spacing and a daily cap per account — mass messaging gets accounts banned fast
const SEND_MAX_NUMBERS = 20;
const SEND_DAILY_LIMIT = 200;
const SEND_MAX_LENGTH = 4096;
const SEND_EXTRA_DELAY_MIN_MS = 3000;
const SEND_EXTRA_DELAY_MAX_MS = 6000;
// Each account's requests are queued and spaced a random 1.5–3.5 s apart so WhatsApp is less likely to flag it
const BULK_MAX_ROWS = 1000;
const BULK_DELAY_MIN_MS = 1500;
const BULK_DELAY_MAX_MS = 3500;
// Every linked account runs its own headless browser (~200–300 MB RAM each)
const MAX_ACTIVE_SESSIONS = Number(process.env.MAX_ACTIVE_SESSIONS) || 10;
const QR_MAX_RETRIES = 6; // stop showing new QR codes after ~2 minutes without a scan
const JOB_TTL_MS = 24 * 60 * 60 * 1000; // finished jobs are kept for 24 hours
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // stay logged in for 30 days
const DB_FILE = path.join(__dirname, 'data.db');
const AUTH_DIR = path.join(__dirname, '.wwebjs_auth');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- Database ----------------------------------------------------------------

const db = new DatabaseSync(DB_FILE);
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    api_key       TEXT NOT NULL UNIQUE,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS sent_messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    to_number  TEXT NOT NULL,
    message_id TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
  );
`);
// Columns added when each user got their own WhatsApp link
const userColumns = db.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
if (!userColumns.includes('wa_number')) db.exec('ALTER TABLE users ADD COLUMN wa_number TEXT');
if (!userColumns.includes('wa_name')) db.exec('ALTER TABLE users ADD COLUMN wa_name TEXT');

const q = {
  insertUser: db.prepare('INSERT INTO users (email, password_hash, api_key) VALUES (?, ?, ?)'),
  userByEmail: db.prepare('SELECT * FROM users WHERE email = ?'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  userByApiKey: db.prepare('SELECT * FROM users WHERE api_key = ?'),
  firstAdmin: db.prepare('SELECT id FROM users WHERE is_admin = 1 ORDER BY id LIMIT 1'),
  allUserIds: db.prepare('SELECT id, wa_number FROM users ORDER BY id'),
  setApiKey: db.prepare('UPDATE users SET api_key = ? WHERE id = ?'),
  setWhatsApp: db.prepare('UPDATE users SET wa_number = ?, wa_name = ? WHERE id = ?'),
  insertSession: db.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)'),
  sessionUser: db.prepare(`SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id
                           WHERE s.token_hash = ? AND s.expires_at > ?`),
  deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
  deleteExpiredSessions: db.prepare('DELETE FROM sessions WHERE expires_at <= ?'),
  logSent: db.prepare('INSERT INTO sent_messages (user_id, to_number, message_id) VALUES (?, ?, ?)'),
  sentToday: db.prepare(`SELECT COUNT(*) AS n FROM sent_messages
                         WHERE user_id = ? AND created_at >= datetime('now', 'start of day')`),
};

// --- Auth helpers --------------------------------------------------------------

const scrypt = promisify(crypto.scrypt);

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, 64);
  return `scrypt:${salt.toString('hex')}:${hash.toString('hex')}`;
}

async function verifyPassword(password, stored) {
  const [, saltHex, hashHex] = stored.split(':');
  const hash = await scrypt(password, Buffer.from(saltHex, 'hex'), 64);
  return crypto.timingSafeEqual(hash, Buffer.from(hashHex, 'hex'));
}

const newApiKey = () => 'wac_' + crypto.randomBytes(24).toString('hex');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

function getCookie(req, name) {
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return decodeURIComponent(v.join('='));
  }
  return null;
}

function startSession(req, res, userId) {
  const token = crypto.randomBytes(32).toString('hex');
  q.insertSession.run(sha256(token), userId, Date.now() + SESSION_TTL_MS);
  res.setHeader('Set-Cookie', [
    `sid=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Lax',
    `Max-Age=${SESSION_TTL_MS / 1000}`, req.secure ? 'Secure' : '',
  ].filter(Boolean).join('; '));
}

function currentUser(req) {
  const token = getCookie(req, 'sid');
  return token ? q.sessionUser.get(sha256(token), Date.now()) : undefined;
}

function publicUser(user) {
  return { email: user.email, api_key: user.api_key };
}

setInterval(() => q.deleteExpiredSessions.run(Date.now()), 60 * 60 * 1000).unref();

// --- WhatsApp sessions (one per user) ---------------------------------------

// whatsapp-web.js sometimes rejects promises internally (e.g. during logout); log them instead of crashing
process.on('unhandledRejection', (err) => console.error('Unhandled error:', err && err.message ? err.message : err));

class WhatsAppSession {
  constructor(userId) {
    this.userId = userId;
    this.client = null;
    this.state = 'not_linked'; // not_linked | starting | qr | ready | disconnected
    this.qr = null;
    this.stopped = true;
    this.restarting = false;
    this.queue = Promise.resolve();
    this.lastRequestAt = 0;
    this.activeJobId = null;
  }

  get dataDir() {
    return path.join(AUTH_DIR, `session-user-${this.userId}`);
  }

  get running() {
    return Boolean(this.client) || this.restarting;
  }

  log(...args) {
    console.log(`[user ${this.userId}]`, ...args);
  }

  start() {
    if (this.client) return;
    this.stopped = false;
    this.state = 'starting';
    this.qr = null;
    const client = new Client({
      // Each user's login is saved in .wwebjs_auth/session-user-<id>, so they scan the QR only once
      authStrategy: new LocalAuth({ clientId: `user-${this.userId}`, dataPath: AUTH_DIR }),
      qrMaxRetries: QR_MAX_RETRIES,
      puppeteer: {
        headless: true,
        executablePath: BROWSER_PATH,
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
      },
    });
    this.client = client;
    this.log('Starting WhatsApp…');
    const current = () => this.client === client; // ignore events from a client we already replaced

    client.on('qr', async (qr) => {
      if (!current()) return;
      if (this.state !== 'qr') this.log('Waiting for the QR code to be scanned.');
      this.state = 'qr';
      this.qr = await QRCode.toDataURL(qr);
    });

    client.on('authenticated', () => {
      if (current()) this.log('WhatsApp login accepted, loading chats…');
    });

    client.on('ready', () => {
      if (!current()) return;
      this.state = 'ready';
      this.qr = null;
      const number = client.info && client.info.wid ? client.info.wid.user : null;
      const name = (client.info && client.info.pushname) || null;
      q.setWhatsApp.run(number, name, this.userId);
      this.log('WhatsApp ready:', number ? '+' + number : '(unknown number)');
    });

    client.on('auth_failure', (msg) => {
      if (!current()) return;
      this.state = 'disconnected';
      this.log('Authentication failed:', msg);
    });

    client.on('disconnected', (reason) => {
      if (!current()) return;
      this.log('WhatsApp disconnected:', reason);
      if (reason === 'LOGOUT') this.unlink(false); // unlinked from the phone
      else if (/max qrcode retries/i.test(String(reason))) this.stop(); // nobody scanned the QR code
      else this.restart();
    });

    client.initialize().catch((err) => {
      if (!current()) return;
      this.log('Could not start WhatsApp:', err.message);
      this.restart();
    });
  }

  // Close the old browser completely before starting a new one; two browsers can't share the session folder
  async restart() {
    if (this.restarting || this.stopped) return;
    this.restarting = true;
    const old = this.client;
    this.client = null;
    this.state = 'starting';
    this.qr = null;
    try {
      if (old) await old.destroy().catch(() => {});
      await sleep(3000);
    } finally {
      this.restarting = false;
    }
    if (!this.stopped) this.start();
  }

  async stop() {
    this.stopped = true;
    const old = this.client;
    this.client = null;
    this.state = 'not_linked';
    this.qr = null;
    if (old) await old.destroy().catch(() => {});
  }

  // Remove the link: log out of WhatsApp (if we still can) and delete the saved login
  async unlink(logoutFromWhatsApp) {
    const old = this.client;
    const wasReady = this.state === 'ready';
    this.stopped = true;
    this.client = null;
    this.state = 'not_linked';
    this.qr = null;
    if (old) {
      if (logoutFromWhatsApp && wasReady) await old.logout().catch(() => {});
      await old.destroy().catch(() => {});
    }
    await sleep(1000);
    await fs.promises.rm(this.dataDir, { recursive: true, force: true, maxRetries: 5 })
      .catch((err) => this.log('Could not delete saved session:', err.message));
    q.setWhatsApp.run(null, null, this.userId);
  }

  // Every request for this account goes through one queue, so parallel API calls can't flood WhatsApp
  queued(task) {
    const run = this.queue.then(async () => {
      const gap = BULK_DELAY_MIN_MS + Math.random() * (BULK_DELAY_MAX_MS - BULK_DELAY_MIN_MS);
      const wait = this.lastRequestAt + gap - Date.now();
      if (wait > 0) await sleep(wait);
      if (this.state !== 'ready') throw new Error('WhatsApp is not connected');
      try {
        return await task(this.client);
      } finally {
        this.lastRequestAt = Date.now();
      }
    });
    this.queue = run.catch(() => {});
    return run;
  }

  // A number's WhatsApp ID (null = not on WhatsApp); retries once because lookups fail intermittently
  async getWid(client, number) {
    try {
      return await client.getNumberId(number);
    } catch (err) {
      await sleep(1500);
      if (this.state !== 'ready') throw err;
      return await client.getNumberId(number);
    }
  }

  isRegistered(number) {
    return this.queued(async (client) => Boolean(await this.getWid(client, number)));
  }

  checkWithProfile(number) {
    return this.queued(async (client) => {
      const wid = await this.getWid(client, number);
      return wid ? getProfile(client, wid) : null;
    });
  }

  // Check the number first so we never open chats with numbers that aren't on WhatsApp
  send(number, message) {
    return this.queued(async (client) => {
      const wid = await this.getWid(client, number);
      if (!wid) return null;
      const sent = await client.sendMessage(wid._serialized, message);
      await sleep(SEND_EXTRA_DELAY_MIN_MS + Math.random() * (SEND_EXTRA_DELAY_MAX_MS - SEND_EXTRA_DELAY_MIN_MS));
      return (sent && sent.id && sent.id._serialized) || 'sent';
    });
  }
}

const waSessions = new Map(); // userId -> WhatsAppSession
function sessionFor(userId) {
  if (!waSessions.has(userId)) waSessions.set(userId, new WhatsAppSession(userId));
  return waSessions.get(userId);
}
const runningSessions = () => [...waSessions.values()].filter((s) => s.running).length;

// Ask WhatsApp for the profile photo link directly. (client.getProfilePicUrl would open a new empty chat
// with every number checked, which clutters the linked account.)
async function fetchProfilePicUrl(client, id) {
  return client.pupPage.evaluate(async (id) => {
    const wid = window.require('WAWebWidFactory').createWid(id);
    const contact = window.require('WAWebCollections').Contact.get(wid);
    try {
      const pic = await window.require('WAWebContactProfilePicThumbBridge')
        .requestProfilePicFromServer(contact || { id: wid });
      return (pic && pic.eurl) || null;
    } catch {
      return null; // no photo, or hidden by privacy settings
    }
  }, id).catch(() => null);
}

// WhatsApp @username, if the person has set one (whatsapp-web.js doesn't expose it yet)
async function fetchUsername(client, id) {
  return client.pupPage.evaluate((id) => {
    const contact = window.require('WAWebCollections').Contact.get(id);
    return (contact && contact.username) || null;
  }, id).catch(() => null);
}

// Collect whatever public profile data the person's privacy settings allow. Each piece is optional.
async function getProfile(client, wid) {
  const id = wid._serialized;
  const optional = (promise) => promise.catch(() => null);
  const contact = await optional(client.getContactById(id));
  const [picUrl, about, username] = await Promise.all([
    fetchProfilePicUrl(client, id),
    contact ? optional(contact.getAbout()) : null,
    fetchUsername(client, id),
  ]);

  let picture = null;
  if (picUrl) {
    // Fetch the photo here: WhatsApp's image links expire quickly and may not load from other sites
    try {
      const r = await fetch(picUrl, { signal: AbortSignal.timeout(10_000) });
      if (r.ok) {
        const type = r.headers.get('content-type') || 'image/jpeg';
        picture = `data:${type};base64,${Buffer.from(await r.arrayBuffer()).toString('base64')}`;
      }
    } catch {}
  }

  const profile = {
    picture,
    name: (contact && (contact.pushname || contact.verifiedName || contact.name)) || null,
    about: (about && about.trim()) || null,
    username: username || null,
    is_business: Boolean(contact && contact.isBusiness),
    is_enterprise: Boolean(contact && contact.isEnterprise),
    verified_name: (contact && contact.verifiedName) || null,
    business: null,
  };
  const bp = contact && contact.businessProfile;
  if (bp) {
    const websites = (bp.website || []).map((w) => (typeof w === 'string' ? w : w && w.url)).filter(Boolean);
    profile.business = {
      category: (bp.categories || []).map((c) => c.localized_display_name || c.name).filter(Boolean).join(', ') || null,
      description: bp.description || null,
      email: bp.email || null,
      website: websites.length ? websites : null,
      address: bp.address || null,
    };
  }
  return profile;
}

// Before per-user links, the single server session lived in .wwebjs_auth/session; hand it to the first admin
function migrateLegacySession() {
  const legacy = path.join(AUTH_DIR, 'session');
  const admin = q.firstAdmin.get();
  if (!admin || !fs.existsSync(legacy)) return;
  const target = sessionFor(admin.id).dataDir;
  if (fs.existsSync(target)) return;
  try {
    fs.renameSync(legacy, target);
    console.log(`Moved the existing WhatsApp login to user ${admin.id}.`);
  } catch (err) {
    console.warn('Could not move the existing WhatsApp login:', err.message);
  }
}

// Reconnect everyone who had linked WhatsApp before the restart, a few seconds apart to spread the load
async function resumeSessions() {
  for (const { id, wa_number } of q.allUserIds.all()) {
    const session = sessionFor(id);
    if (!wa_number && !fs.existsSync(session.dataDir)) continue;
    if (runningSessions() >= MAX_ACTIVE_SESSIONS) {
      console.warn(`MAX_ACTIVE_SESSIONS (${MAX_ACTIVE_SESSIONS}) reached; not reconnecting user ${id}.`);
      continue;
    }
    session.start();
    await sleep(5000);
  }
}

// --- Helpers ---------------------------------------------------------------

function normalizeNumber(input) {
  if (typeof input === 'number') input = input.toFixed(0);
  if (typeof input !== 'string') return null;
  let digits = input.replace(/[^\d+]/g, '');
  if (digits.startsWith('+')) digits = digits.slice(1);
  else if (digits.startsWith('00')) digits = digits.slice(2);
  digits = digits.replace(/\D/g, '');
  // E.164: max 15 digits; shortest real numbers with country code are ~8
  if (digits.length < 8 || digits.length > 15) return null;
  return digits;
}

function makeRateLimiter(limit, keyOf, sendError) {
  const hits = new Map(); // key -> timestamps of recent requests
  return (req, res, next) => {
    const now = Date.now();
    const k = keyOf(req);
    const recent = (hits.get(k) || []).filter((t) => now - t < 60_000);
    if (recent.length >= limit) return sendError(res);
    recent.push(now);
    hits.set(k, recent);
    next();
  };
}

// Turn whatever ExcelJS gives us (number, string, rich text, formula) into plain text
function cellText(value) {
  if (value == null) return '';
  if (typeof value === 'number') return value.toFixed(0);
  if (typeof value === 'object') {
    if (value.richText) return value.richText.map((t) => t.text).join('');
    if ('result' in value) return cellText(value.result);
    if (value.text) return String(value.text);
  }
  return String(value).trim();
}

class UserError extends Error {
  constructor(message, httpStatus = 400) {
    super(message);
    this.httpStatus = httpStatus;
  }
}

async function readNumbers(buffer) {
  const workbook = new ExcelJS.Workbook();
  try {
    await workbook.xlsx.load(buffer);
  } catch {
    throw new UserError('Could not read this file. Make sure it is a valid .xlsx Excel file.');
  }
  const sheet = workbook.worksheets[0];
  if (!sheet) throw new UserError('The Excel file has no sheets.');

  let col = null;
  sheet.getRow(1).eachCell((cell, colNumber) => {
    if (cellText(cell.value).toLowerCase() === 'numbers') col = colNumber;
  });
  if (!col) throw new UserError('Could not find a column named "numbers" in the first row.');

  const numbers = [];
  for (let r = 2; r <= sheet.rowCount; r++) {
    const text = cellText(sheet.getRow(r).getCell(col).value);
    if (text) numbers.push(text);
  }
  return numbers;
}

async function buildResultFile(results) {
  const workbook = new ExcelJS.Workbook();
  const sheet = workbook.addWorksheet('Results');
  sheet.columns = [
    { header: 'numbers', key: 'number', width: 22 },
    { header: 'whatsapp', key: 'flag', width: 16 },
  ];
  sheet.getRow(1).font = { bold: true };
  for (const row of results) {
    const added = sheet.addRow({ number: row.number, flag: row.flag });
    const color = row.flag === 'Yes' ? 'FF1E8E3E' : row.flag === 'No' ? 'FFD93025' : 'FF80868B';
    added.getCell('flag').font = { color: { argb: color }, bold: true };
  }
  return workbook.xlsx.writeBuffer();
}

// --- Excel jobs (website) ----------------------------------------------------

const NOT_LINKED_MESSAGE = 'Your WhatsApp is not connected. Link it on the dashboard first.';

// One job per user at a time, since each user's checks go through their own WhatsApp session
const jobs = new Map(); // id -> job

function createJob(numbers, session) {
  if (session.state !== 'ready') throw new UserError(NOT_LINKED_MESSAGE, 503);
  if (session.activeJobId) throw new UserError('Another file is still being checked. Wait for it to finish.', 409);
  if (numbers.length === 0) throw new UserError('The "numbers" column is empty.');
  if (numbers.length > BULK_MAX_ROWS) {
    throw new UserError(`Too many numbers (${numbers.length}). The limit is ${BULK_MAX_ROWS} per file.`);
  }
  const id = crypto.randomUUID();
  const job = {
    id, ownerId: session.userId, status: 'running', total: numbers.length, done: 0,
    results: [], file: null, error: null, finishedAt: null,
  };
  jobs.set(id, job);
  session.activeJobId = id;
  runJob(job, numbers, session);
  return job;
}

async function runJob(job, numbers, session) {
  const cache = new Map(); // normalized number -> flag, so duplicates are checked once
  try {
    for (const raw of numbers) {
      if (job.status === 'cancelled') break;
      const number = normalizeNumber(raw);
      let flag;
      if (!number) {
        flag = 'Invalid number';
      } else if (cache.has(number)) {
        flag = cache.get(number);
      } else {
        // Wait out a reconnect instead of marking everything as an error; give up if the user unlinks
        while (session.state !== 'ready' && session.state !== 'not_linked') {
          if (job.status === 'cancelled') break;
          await sleep(2000);
        }
        if (job.status === 'cancelled') break;
        if (session.state === 'not_linked') throw new Error('WhatsApp was unlinked while the file was being checked.');
        try {
          flag = (await session.isRegistered(number)) ? 'Yes' : 'No';
        } catch (err) {
          console.error('Bulk check failed for', number, err.message);
          flag = 'Error';
        }
        if (flag !== 'Error') cache.set(number, flag);
      }
      job.results.push({ number: String(raw), flag });
      job.done++;
    }
    job.file = await buildResultFile(job.results);
    if (job.status !== 'cancelled') job.status = 'done';
  } catch (err) {
    job.status = 'error';
    job.error = err.message;
    job.file = await buildResultFile(job.results).catch(() => null);
  } finally {
    job.finishedAt = Date.now();
    session.activeJobId = null;
  }
}

// Drop finished jobs after JOB_TTL_MS so memory doesn't grow forever
setInterval(() => {
  const cutoff = Date.now() - JOB_TTL_MS;
  for (const [id, job] of jobs) {
    if (job.finishedAt && job.finishedAt < cutoff) jobs.delete(id);
  }
}, 60 * 60 * 1000).unref();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

// --- HTTP server -----------------------------------------------------------

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// --- Accounts ---

const authRateLimit = makeRateLimiter(AUTH_RATE_LIMIT_PER_MINUTE, (req) => req.ip, (res) =>
  res.status(429).json({ error: 'Too many attempts. Please wait a minute and try again.' }));

app.post('/auth/register', authRateLimit, async (req, res) => {
  const email = String((req.body && req.body.email) || '').trim().toLowerCase();
  const password = String((req.body && req.body.password) || '');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return res.status(400).json({ error: 'Enter a valid email address.' });
  }
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  if (q.userByEmail.get(email)) return res.status(409).json({ error: 'An account with this email already exists.' });

  const { lastInsertRowid } = q.insertUser.run(email, await hashPassword(password), newApiKey());
  startSession(req, res, lastInsertRowid);
  res.status(201).json(publicUser(q.userById.get(lastInsertRowid)));
});

app.post('/auth/login', authRateLimit, async (req, res) => {
  const email = String((req.body && req.body.email) || '').trim().toLowerCase();
  const password = String((req.body && req.body.password) || '');
  const user = q.userByEmail.get(email);
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return res.status(401).json({ error: 'Wrong email or password.' });
  }
  startSession(req, res, user.id);
  res.json(publicUser(user));
});

app.post('/auth/logout', (req, res) => {
  const token = getCookie(req, 'sid');
  if (token) q.deleteSession.run(sha256(token));
  res.setHeader('Set-Cookie', 'sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
  res.json({ ok: true });
});

function requireUser(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'Please log in.' });
  req.user = user;
  next();
}

app.get('/auth/me', requireUser, (req, res) => res.json(publicUser(req.user)));

app.post('/auth/api-key', requireUser, (req, res) => {
  q.setApiKey.run(newApiKey(), req.user.id);
  res.json(publicUser(q.userById.get(req.user.id)));
});

// --- The user's own WhatsApp link ---

function whatsappStatus(user) {
  const session = sessionFor(user.id);
  const fresh = q.userById.get(user.id);
  return {
    state: session.state,
    qr: session.state === 'qr' ? session.qr : null,
    number: session.state === 'ready' && fresh.wa_number ? '+' + fresh.wa_number : null,
    name: session.state === 'ready' ? fresh.wa_name : null,
    sent_today: q.sentToday.get(user.id).n,
    daily_limit: SEND_DAILY_LIMIT,
  };
}

app.get('/api/whatsapp', requireUser, (req, res) => res.json(whatsappStatus(req.user)));

app.post('/api/whatsapp/link', requireUser, (req, res) => {
  const session = sessionFor(req.user.id);
  if (!session.running) {
    if (runningSessions() >= MAX_ACTIVE_SESSIONS) {
      return res.status(503).json({ error: 'The server is at capacity right now. Please try again later.' });
    }
    session.start();
  }
  res.json(whatsappStatus(req.user));
});

app.post('/api/whatsapp/unlink', requireUser, async (req, res) => {
  const session = sessionFor(req.user.id);
  const job = session.activeJobId && jobs.get(session.activeJobId);
  if (job && job.status === 'running') job.status = 'cancelled';
  await session.unlink(true);
  res.json(whatsappStatus(req.user));
});

// --- Website checks (require login and a linked WhatsApp) ---

const webRateLimit = makeRateLimiter(RATE_LIMIT_PER_MINUTE, (req) => req.user.id, (res) =>
  res.status(429).json({ error: 'Too many requests. Please wait a minute and try again.' }));

app.post('/api/check', requireUser, webRateLimit, async (req, res) => {
  const session = sessionFor(req.user.id);
  if (session.state !== 'ready') return res.status(503).json({ error: NOT_LINKED_MESSAGE });
  const number = normalizeNumber(req.body.number);
  if (!number) {
    return res.status(400).json({ error: 'Enter a valid number with country code, e.g. +201001234567' });
  }
  try {
    const profile = await session.checkWithProfile(number);
    res.json({ number: '+' + number, registered: Boolean(profile), profile });
  } catch (err) {
    console.error('Check failed:', err.message);
    res.status(500).json({ error: 'Could not check this number right now. Try again.' });
  }
});

app.post('/api/bulk', requireUser, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) throw new UserError('Please choose an Excel (.xlsx) file.');
    const job = createJob(await readNumbers(req.file.buffer), sessionFor(req.user.id));
    res.json({ id: job.id, total: job.total });
  } catch (err) {
    if (err instanceof UserError) return res.status(err.httpStatus).json({ error: err.message });
    console.error('Bulk upload failed:', err);
    res.status(500).json({ error: 'Something went wrong on the server.' });
  }
});

function findOwnJob(req, res) {
  const job = jobs.get(req.params.id);
  if (!job || job.ownerId !== req.user.id) {
    res.status(404).json({ error: 'Job not found.' });
    return null;
  }
  return job;
}

app.get('/api/bulk/:id', requireUser, (req, res) => {
  const job = findOwnJob(req, res);
  if (!job) return;
  const count = (flag) => job.results.filter((r) => r.flag === flag).length;
  res.json({
    status: job.status,
    total: job.total,
    done: job.done,
    yes: count('Yes'),
    no: count('No'),
    error: job.error,
    downloadable: Boolean(job.file),
  });
});

app.post('/api/bulk/:id/cancel', requireUser, (req, res) => {
  const job = findOwnJob(req, res);
  if (!job) return;
  if (job.status === 'running') job.status = 'cancelled';
  res.json({ ok: true });
});

app.get('/api/bulk/:id/download', requireUser, (req, res) => {
  const job = findOwnJob(req, res);
  if (!job) return;
  if (!job.file) return res.status(404).json({ error: 'Result file is not ready.' });
  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename="whatsapp_results.xlsx"');
  res.send(Buffer.from(job.file));
});

// --- Public API v1: POST /check and POST /send, each using the caller's own WhatsApp (see /docs.html) ---

const v1 = express.Router();

const apiError = (res, httpStatus, code, message) =>
  res.status(httpStatus).json({ error: { code, message } });

// Allow calls from browsers on other sites
v1.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

function requireApiKey(req, res, next) {
  const key = req.get('X-API-Key') || (req.get('Authorization') || '').replace(/^Bearer\s+/i, '');
  const user = key && q.userByApiKey.get(key);
  if (!user) return apiError(res, 401, 'unauthorized', 'Missing or invalid API key. Send it in the X-API-Key header.');
  req.user = user;
  next();
}

function requireLinkedWhatsApp(req, res, next) {
  req.wa = sessionFor(req.user.id);
  if (req.wa.state !== 'ready') {
    return apiError(res, 503, 'whatsapp_not_connected',
      'The WhatsApp account for this API key is not connected. Log in to the site and link it from the dashboard.');
  }
  next();
}

const apiRateLimit = makeRateLimiter(API_RATE_LIMIT_PER_MINUTE, (req) => req.user.id, (res) =>
  apiError(res, 429, 'rate_limited', `Rate limit is ${API_RATE_LIMIT_PER_MINUTE} requests per minute.`));

const FLAG_TO_API = {
  Yes: { status: 'registered', whatsapp: true },
  No: { status: 'not_registered', whatsapp: false },
  'Invalid number': { status: 'invalid', whatsapp: null },
  Error: { status: 'error', whatsapp: null },
};

function toResult(input, normalized, flag) {
  return { input: String(input), number: normalized ? '+' + normalized : null, ...FLAG_TO_API[flag] };
}

// "number" is a single string or an array of up to CHECK_MAX_NUMBERS strings
v1.post('/check', requireApiKey, apiRateLimit, requireLinkedWhatsApp, async (req, res) => {
  const input = (req.body || {}).number;
  if (input == null || input === '' || (Array.isArray(input) && input.length === 0)) {
    return apiError(res, 400, 'missing_number', 'Provide "number" as a string or an array of strings.');
  }

  if (!Array.isArray(input)) {
    const number = normalizeNumber(input);
    if (!number) return res.json(toResult(input, null, 'Invalid number'));
    try {
      res.json(toResult(input, number, (await req.wa.isRegistered(number)) ? 'Yes' : 'No'));
    } catch (err) {
      console.error('API check failed:', err.message);
      apiError(res, 502, 'check_failed', 'WhatsApp did not answer. Try again in a moment.');
    }
    return;
  }

  const list = input.filter((n) => n != null && String(n).trim() !== '');
  if (list.length > CHECK_MAX_NUMBERS) {
    return apiError(res, 400, 'too_many_numbers',
      `Too many numbers (${list.length}). Send at most ${CHECK_MAX_NUMBERS} per request.`);
  }

  // Stop checking if the caller gives up and closes the connection
  let aborted = false;
  res.on('close', () => { if (!res.writableEnded) aborted = true; });

  const cache = new Map(); // duplicates in the same request are checked once
  const results = [];
  for (const raw of list) {
    if (aborted) return;
    const number = normalizeNumber(raw);
    let flag;
    if (!number) flag = 'Invalid number';
    else if (cache.has(number)) flag = cache.get(number);
    else {
      try {
        flag = (await req.wa.isRegistered(number)) ? 'Yes' : 'No';
        cache.set(number, flag);
      } catch (err) {
        console.error('API check failed for', number, err.message);
        flag = 'Error';
      }
    }
    results.push(toResult(raw, number, flag));
  }
  const count = (status) => results.filter((r) => r.status === status).length;
  res.json({
    total: results.length,
    summary: {
      registered: count('registered'),
      not_registered: count('not_registered'),
      invalid: count('invalid'),
      error: count('error'),
    },
    results,
  });
});

// "number" is a single string or an array of up to SEND_MAX_NUMBERS strings; "message" is the text to send.
// Messages go out from the WhatsApp account the API key's owner linked.
v1.post('/send', requireApiKey, apiRateLimit, requireLinkedWhatsApp, async (req, res) => {
  const { number: input, message } = req.body || {};
  if (input == null || input === '' || (Array.isArray(input) && input.length === 0)) {
    return apiError(res, 400, 'missing_number', 'Provide "number" as a string or an array of strings.');
  }
  if (typeof message !== 'string' || message.trim() === '') {
    return apiError(res, 400, 'missing_message', 'Provide the text to send in "message".');
  }
  if (message.length > SEND_MAX_LENGTH) {
    return apiError(res, 400, 'message_too_long', `The message is longer than ${SEND_MAX_LENGTH} characters.`);
  }
  const single = !Array.isArray(input);
  const list = (single ? [input] : input).filter((n) => n != null && String(n).trim() !== '');
  if (list.length > SEND_MAX_NUMBERS) {
    return apiError(res, 400, 'too_many_numbers', `Too many numbers (${list.length}). Send to at most ${SEND_MAX_NUMBERS} per request.`);
  }
  const remaining = SEND_DAILY_LIMIT - q.sentToday.get(req.user.id).n;
  if (remaining <= 0) {
    return apiError(res, 429, 'daily_limit_reached', `The daily limit of ${SEND_DAILY_LIMIT} messages has been reached. Try again tomorrow (UTC).`);
  }

  let aborted = false;
  res.on('close', () => { if (!res.writableEnded) aborted = true; });

  const done = new Set(); // don't message the same number twice in one request
  const results = [];
  let sentCount = 0;
  for (const raw of list) {
    if (aborted) return;
    const number = normalizeNumber(raw);
    const result = { input: String(raw), number: number ? '+' + number : null, status: null, message_id: null };
    if (!number) result.status = 'invalid';
    else if (done.has(number)) result.status = 'duplicate';
    else if (sentCount >= remaining) result.status = 'daily_limit_reached';
    else {
      done.add(number);
      try {
        const messageId = await req.wa.send(number, message);
        if (messageId) {
          q.logSent.run(req.user.id, number, messageId);
          sentCount++;
          Object.assign(result, { status: 'sent', message_id: messageId });
        } else {
          result.status = 'not_registered';
        }
      } catch (err) {
        console.error('Send failed for', number, err.message);
        result.status = 'error';
      }
    }
    results.push(result);
  }

  if (single) return res.json(results[0]);
  const count = (status) => results.filter((r) => r.status === status).length;
  res.json({
    total: results.length,
    summary: {
      sent: count('sent'),
      not_registered: count('not_registered'),
      invalid: count('invalid'),
      duplicate: count('duplicate'),
      daily_limit_reached: count('daily_limit_reached'),
      error: count('error'),
    },
    results,
  });
});

v1.use((req, res) => apiError(res, 404, 'not_found', 'Unknown API endpoint. Available: POST /api/v1/check, POST /api/v1/send.'));

app.use('/api/v1', v1);

// Errors from body parsing / uploads (raised before the routers run)
app.use((err, req, res, next) => {
  let httpStatus = 500, code = 'internal_error', message = 'Something went wrong on the server.';
  if (err instanceof multer.MulterError) [httpStatus, code, message] = [400, 'invalid_upload', err.message];
  else if (err.type === 'entity.parse.failed') [httpStatus, code, message] = [400, 'invalid_json', 'Request body is not valid JSON.'];
  else if (err.type === 'entity.too.large') [httpStatus, code, message] = [413, 'too_large', 'Request body is too large.'];
  else console.error('Server error:', err);
  if (req.path.startsWith('/api/v1')) apiError(res, httpStatus, code, message);
  else res.status(httpStatus).json({ error: message });
});

migrateLegacySession();

app.listen(PORT, () => {
  console.log(`WhatsApp Checker running at http://localhost:${PORT}`);
  console.log(`API docs at http://localhost:${PORT}/docs.html`);
  resumeSessions();
});
