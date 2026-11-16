require('dotenv').config();
const express = require('express');
const cors = require('cors');
const http = require('http');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { Server } = require('socket.io');
const db = require('./db');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const CLIENT_SCHEME = process.env.CLIENT_CALLBACK_SCHEME || 'mezoxmusic';

function sign(user) {
  return jwt.sign({ uid: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
}
function getUserById(id) { return db.prepare('SELECT * FROM users WHERE id = ?').get(id); }
function getUserByUsername(username) {
  if (!username) return null;
  return db.prepare('SELECT * FROM users WHERE username = ?').get(String(username).toLowerCase().trim());
}
function publicProfile(u, token) {
  return { username: u.username, displayName: u.display_name, age: u.age || 0, token: token || undefined };
}
function redirectToApp(res, user) {
  const token = sign(user);
  const url = `${CLIENT_SCHEME}://auth?token=${encodeURIComponent(token)}&username=${encodeURIComponent(user.username)}&displayName=${encodeURIComponent(user.display_name)}&age=${user.age || 0}`;
  res.redirect(url);
}

// --- Local auth ---
app.post('/auth/register', async (req, res) => {
  try {
    const { username, displayName, age, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    const uname = String(username).toLowerCase().trim();
    if (getUserByUsername(uname)) return res.status(409).json({ error: 'Username taken' });
    const hash = await bcrypt.hash(String(password), 10);
    const info = db.prepare(
      'INSERT INTO users (username, display_name, age, password_hash, provider) VALUES (?,?,?,?,?)'
    ).run(uname, String(displayName || uname), Number(age || 0), hash, 'local');
    const user = getUserById(info.lastInsertRowid);
    res.json(publicProfile(user, sign(user)));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const user = getUserByUsername(String(username || ''));
    if (!user || !user.password_hash) return res.status(401).json({ error: 'Invalid credentials' });
    const ok = await bcrypt.compare(String(password || ''), user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
    res.json(publicProfile(user, sign(user)));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- OAuth token upsert (Google/Apple idToken from client) ---
// Production: verify idToken signature with provider JWKS before trusting.
app.post('/auth/oauth', async (req, res) => {
  try {
    const { provider, idToken, accessToken, email, displayName } = req.body || {};
    if (!provider) return res.status(400).json({ error: 'provider required' });
    const raw = String(idToken || accessToken || email || `${provider}_${Date.now()}`);
    const pid = crypto.createHash('sha256').update(raw).digest('hex').slice(0, 24);
    let user = db.prepare('SELECT * FROM users WHERE provider = ? AND provider_id = ?').get(provider, pid);
    if (!user) {
      const base = (email ? email.split('@')[0] : `${provider}_${pid.slice(0, 6)}`).toLowerCase().replace(/[^a-z0-9_]/g, '') || provider;
      let uname = base, n = 1;
      while (getUserByUsername(uname)) uname = `${base}${n++}`;
      const info = db.prepare(
        'INSERT INTO users (username, display_name, age, provider, provider_id) VALUES (?,?,?,?,?)'
      ).run(uname, String(displayName || uname), 0, provider, pid);
      user = getUserById(info.lastInsertRowid);
    }
    res.json(publicProfile(user, sign(user)));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- Discord OAuth ---
app.get('/auth/discord/start', (req, res) => {
  const cid = process.env.DISCORD_CLIENT_ID;
  const redirect = encodeURIComponent(process.env.DISCORD_REDIRECT_URI || `${BASE_URL}/auth/discord/callback`);
  if (!cid) return res.status(500).send('DISCORD_CLIENT_ID not configured');
  res.redirect(`https://discord.com/api/oauth2/authorize?client_id=${cid}&redirect_uri=${redirect}&response_type=code&scope=identify%20email`);
});
app.get('/auth/discord/callback', async (req, res) => {
  try {
    const code = req.query.code;
    const tokenRes = await axios.post('https://discord.com/api/oauth2/token', new URLSearchParams({
      client_id: process.env.DISCORD_CLIENT_ID,
      client_secret: process.env.DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code: String(code),
      redirect_uri: process.env.DISCORD_REDIRECT_URI || `${BASE_URL}/auth/discord/callback`,
    }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    const access = tokenRes.data.access_token;
    const me = await axios.get('https://discord.com/api/users/@me', { headers: { Authorization: `Bearer ${access}` } });
    const d = me.data;
    let user = db.prepare('SELECT * FROM users WHERE provider = ? AND provider_id = ?').get('discord', String(d.id));
    if (!user) {
      let uname = String(d.username || `discord${d.id}`).toLowerCase().replace(/[^a-z0-9_]/g, '') || `discord${d.id}`;
      let n = 1; const base = uname; while (getUserByUsername(uname)) uname = `${base}${n++}`;
      const info = db.prepare('INSERT INTO users (username, display_name, age, provider, provider_id) VALUES (?,?,?,?,?)')
        .run(uname, d.global_name || d.username || uname, 0, 'discord', String(d.id));
      user = getUserById(info.lastInsertRowid);
    }
    redirectToApp(res, user);
  } catch (e) { res.status(500).send('Discord auth failed: ' + e.message); }
});

// --- Telegram Login Widget flow ---
function verifyTelegramAuth(data) {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  if (!botToken) return false;
  const secret = crypto.createHash('sha256').update(botToken).digest();
  const { hash, ...rest } = data;
  const checkString = Object.keys(rest).sort().map(k => `${k}=${rest[k]}`).join('\n');
  const hmac = crypto.createHmac('sha256', secret).update(checkString).digest('hex');
  return hmac === hash;
}
app.get('/auth/telegram/start', (req, res) => {
  const bot = process.env.TELEGRAM_BOT_USERNAME || '';
  const cb = `${BASE_URL}/auth/telegram/callback`;
  res.type('html').send(`<!doctype html><html><body style="font-family:sans-serif;background:#0b0b0f;color:#fff;display:flex;align-items:center;justify-content:center;height:100vh">
  <div><h2>MEZOX MUSIC — Telegram Login</h2>
  <script async src="https://telegram.org/js/telegram-widget.js?22" data-telegram-login="${bot}" data-size="large" data-auth-url="${cb}" data-request-access="write"></script>
  <p style="color:#aaa">Set TELEGRAM_BOT_USERNAME and TELEGRAM_BOT_TOKEN on server.</p></div></body></html>`);
});
app.get('/auth/telegram/callback', (req, res) => {
  try {
    const data = req.query;
    if (!verifyTelegramAuth(data)) return res.status(401).send('Invalid Telegram auth');
    const tid = String(data.id);
    let user = db.prepare('SELECT * FROM users WHERE provider = ? AND provider_id = ?').get('telegram', tid);
    if (!user) {
      let uname = String(data.username || `tg${tid}`).toLowerCase().replace(/[^a-z0-9_]/g, '') || `tg${tid}`;
      let n = 1; const base = uname; while (getUserByUsername(uname)) uname = `${base}${n++}`;
      const dname = [data.first_name, data.last_name].filter(Boolean).join(' ') || uname;
      const info = db.prepare('INSERT INTO users (username, display_name, age, provider, provider_id) VALUES (?,?,?,?,?)')
        .run(uname, dname, 0, 'telegram', tid);
      user = getUserById(info.lastInsertRowid);
    }
    redirectToApp(res, user);
  } catch (e) { res.status(500).send('Telegram auth failed: ' + e.message); }
});

// --- Friends & invites ---
app.get('/friends', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT u.username, u.display_name as displayName
    FROM friends f JOIN users u ON u.id = f.friend_id
    WHERE f.user_id = ?
  `).all(req.user.uid);
  res.json(rows.map(r => ({ ...r, online: onlineUsers.has(r.username) })));
});
app.get('/friends/invites', auth, (req, res) => {
  const rows = db.prepare(`
    SELECT u.username as fromUsername, u.display_name as fromDisplayName
    FROM invites i JOIN users u ON u.id = i.from_id
    WHERE i.to_id = ?
  `).all(req.user.uid);
  res.json(rows);
});
app.post('/friends/invite', auth, (req, res) => {
  const to = getUserByUsername(req.body.toUsername);
  if (!to) return res.status(404).json({ error: 'User not found' });
  if (to.id === req.user.uid) return res.status(400).json({ error: 'Cannot invite yourself' });
  try {
    db.prepare('INSERT OR IGNORE INTO invites (from_id, to_id) VALUES (?,?)').run(req.user.uid, to.id);
    const from = getUserById(req.user.uid);
    const sockets = userSockets.get(to.username) || [];
    sockets.forEach(sid => io.to(sid).emit('invite_received', { fromUsername: from.username }));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/friends/accept', auth, (req, res) => {
  const from = getUserByUsername(req.body.fromUsername);
  if (!from) return res.status(404).json({ error: 'User not found' });
  const inv = db.prepare('SELECT 1 FROM invites WHERE from_id = ? AND to_id = ?').get(from.id, req.user.uid);
  if (!inv) return res.status(404).json({ error: 'Invite not found' });
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM invites WHERE from_id = ? AND to_id = ?').run(from.id, req.user.uid);
    db.prepare('INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?,?)').run(req.user.uid, from.id);
    db.prepare('INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?,?)').run(from.id, req.user.uid);
  });
  tx();
  const me = getUserById(req.user.uid);
  [me.username, from.username].forEach(u => (userSockets.get(u) || []).forEach(sid => io.to(sid).emit('friends_updated')));
  res.json({ ok: true });
});

// Listen-together room: deterministic room id for a pair
function roomFor(a, b) { return 'lt_' + [a, b].sort().join('__'); }
app.post('/friends/listen/join', auth, (req, res) => {
  const friend = getUserByUsername(req.body.friendUsername);
  if (!friend) return res.status(404).json({ error: 'Friend not found' });
  const me = getUserById(req.user.uid);
  const roomId = roomFor(me.username, friend.username);
  res.json({ roomId });
});

// --- Lyrics (fetched ~10s after playback on client, no AI) ---
app.post('/lyrics', auth, async (req, res) => {
  const { title, artist } = req.body || {};
  const trackName = String(title || '').trim();
  const artistName = String(artist || '').trim();
  if (!trackName && !artistName) return res.json({ lyrics: '' });

  const headers = { 'User-Agent': 'MEZOX-MUSIC/1.0' };
  try {
    // 1) LRCLIB exact/get
    try {
      const r = await axios.get('https://lrclib.net/api/get', {
        params: { artist_name: artistName, track_name: trackName },
        headers, timeout: 8000, validateStatus: () => true,
      });
      if (r.status === 200 && r.data) {
        const lyrics = (r.data.plainLyrics || r.data.syncedLyrics || '').trim();
        if (lyrics) return res.json({ lyrics, source: 'lrclib' });
      }
    } catch (_) {}

    // 2) LRCLIB search
    try {
      const q = `${trackName} ${artistName}`.trim();
      const r = await axios.get('https://lrclib.net/api/search', {
        params: { q },
        headers, timeout: 8000, validateStatus: () => true,
      });
      if (r.status === 200 && Array.isArray(r.data) && r.data.length) {
        const best = r.data[0];
        const lyrics = (best.plainLyrics || best.syncedLyrics || '').trim();
        if (lyrics) return res.json({ lyrics, source: 'lrclib' });
      }
    } catch (_) {}

    // 3) lyrics.ovh fallback
    try {
      if (artistName && trackName) {
        const url = `https://api.lyrics.ovh/v1/${encodeURIComponent(artistName)}/${encodeURIComponent(trackName)}`;
        const r = await axios.get(url, { timeout: 8000, validateStatus: () => true });
        if (r.status === 200 && r.data && r.data.lyrics) {
          return res.json({ lyrics: String(r.data.lyrics).trim(), source: 'lyrics.ovh' });
        }
      }
    } catch (_) {}

    return res.json({ lyrics: 'Lyrics not found for this track.' });
  } catch (e) {
    return res.json({ lyrics: 'Lyrics unavailable right now.' });
  }
});

// --- Socket.IO: presence + listen-together sync ---
const onlineUsers = new Set();           // usernames
const userSockets = new Map();           // username -> [socketId]

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error('unauthorized'));
    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch { next(new Error('unauthorized')); }
});

io.on('connection', (socket) => {
  const username = socket.user.username;
  if (!userSockets.has(username)) userSockets.set(username, []);
  userSockets.get(username).push(socket.id);
  onlineUsers.add(username);

  socket.on('join_room', ({ roomId }) => { if (roomId) socket.join(roomId); });
  socket.on('leave_room', ({ roomId }) => { if (roomId) socket.leave(roomId); });
  socket.on('play_sync', ({ roomId, track }) => {
    if (roomId && track) socket.to(roomId).emit('play_sync', { track });
  });

  socket.on('disconnect', () => {
    const arr = (userSockets.get(username) || []).filter(id => id !== socket.id);
    if (arr.length) userSockets.set(username, arr);
    else { userSockets.delete(username); onlineUsers.delete(username); }
  });
});

app.get('/', (_req, res) => res.json({ ok: true, service: 'MEZOX MUSIC API' }));

server.listen(PORT, () => {
  console.log(`MEZOX server running on ${BASE_URL} (port ${PORT})`);
});
