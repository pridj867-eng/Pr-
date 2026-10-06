const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const PASS = process.env.ADMIN_PASSWORD || 'admin';
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
fs.mkdirSync(DIR, { recursive: true });
const FILE = path.join(DIR, 'db.json');

let db = { users: [], settings: { host: '', sni: '', wsPath: '/ws', tls: true } };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(FILE, 'utf8'))); } catch {}
const save = () => fs.writeFileSync(FILE, JSON.stringify(db, null, 1));
const TOKEN = crypto.createHmac('sha256', PASS).update('pr-config').digest('hex');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const status = (u) => {
  if (!u.enabled) return 'disabled';
  if (u.expireAt && new Date(u.expireAt) < new Date()) return 'expired';
  if (u.limitGB > 0 && u.usedGB >= u.limitGB) return 'expired';
  return 'active';
};

const linksOf = (u, req) => {
  const s = db.settings;
  const host = s.host || req.hostname;
  const sni = s.sni || host;
  const tls = s.tls !== false;
  const out = [];
  for (const proto of u.protocols) {
    for (const port of u.ports) {
      const label = u.name + '-' + proto + '-' + port;
      if (proto === 'vmess') {
        const j = { v: '2', ps: label, add: host, port: String(port), id: u.id, aid: '0', scy: 'auto', net: 'ws',
          type: 'none', host: sni, path: s.wsPath || '/ws', tls: tls ? 'tls' : '', sni: tls ? sni : '', alpn: '', fp: '' };
        out.push('vmess://' + Buffer.from(JSON.stringify(j)).toString('base64'));
        continue;
      }
      const p = new URLSearchParams({
        security: tls ? 'tls' : 'none', sni, type: 'ws', host: sni, path: s.wsPath || '/ws',
      });
      if (proto === 'vless') p.set('encryption', 'none');
      out.push(`${proto}://${u.id}@${host}:${port}?${p}#${encodeURIComponent(u.name + '-' + proto + '-' + port)}`);
    }
  }
  return out;
};

const auth = (req, res, next) =>
  req.headers.authorization === 'Bearer ' + TOKEN ? next() : res.status(401).json({ error: 'unauthorized' });

app.post('/api/login', (req, res) =>
  req.body.password === PASS ? res.json({ token: TOKEN }) : res.status(401).json({ error: 'wrong password' }));

const clean = (b, old = {}) => ({
  id: old.id || crypto.randomUUID(),
  name: String(b.name ?? old.name ?? 'user').slice(0, 40),
  enabled: b.enabled ?? old.enabled ?? true,
  protocols: (b.protocols ?? old.protocols ?? ['vless']).filter((x) => ['vless', 'trojan', 'vmess'].includes(x)),
  ports: (b.ports ?? old.ports ?? [443]).map(Number).filter((n) => n > 0 && n < 65536),
  limitGB: Number(b.limitGB ?? old.limitGB ?? 0),
  usedGB: Number(b.usedGB ?? old.usedGB ?? 0),
  expireAt: b.expireAt ?? old.expireAt ?? '',
  note: String(b.note ?? old.note ?? '').slice(0, 200),
  createdAt: old.createdAt || new Date().toISOString(),
});

app.get('/api/users', auth, (req, res) =>
  res.json(db.users.map((u) => ({ ...u, status: status(u), links: linksOf(u, req) }))));

app.post('/api/users', auth, (req, res) => {
  const n = Math.min(Math.max(parseInt(req.body.count) || 1, 1), 100);
  for (let i = 0; i < n; i++) {
    const u = clean({ ...req.body, name: n > 1 ? `${req.body.name || 'user'}-${i + 1}` : req.body.name });
    db.users.unshift(u);
  }
  save();
  res.json({ ok: true });
});

app.put('/api/users/:id', auth, (req, res) => {
  const i = db.users.findIndex((u) => u.id === req.params.id);
  if (i < 0) return res.status(404).json({ error: 'not found' });
  db.users[i] = clean(req.body, db.users[i]);
  save();
  res.json({ ok: true });
});

app.delete('/api/users/:id', auth, (req, res) => {
  db.users = db.users.filter((u) => u.id !== req.params.id);
  save();
  res.json({ ok: true });
});

app.get('/api/settings', auth, (req, res) => res.json(db.settings));
app.put('/api/settings', auth, (req, res) => {
  db.settings = { ...db.settings, ...req.body };
  save();
  res.json({ ok: true });
});

// Public subscription link (paste into v2rayNG / Hiddify / Streisand ...)
app.get('/sub/:id', (req, res) => {
  const u = db.users.find((x) => x.id === req.params.id);
  if (!u || status(u) !== 'active') return res.status(404).send('');
  const total = Math.round(u.limitGB * 1024 ** 3);
  const exp = u.expireAt ? Math.floor(new Date(u.expireAt) / 1000) : 0;
  res.set({
    'Subscription-Userinfo': `upload=0; download=${Math.round(u.usedGB * 1024 ** 3)}; total=${total}; expire=${exp}`,
    'Profile-Title': 'PR Config',
    'Content-Type': 'text/plain; charset=utf-8',
  });
  res.send(Buffer.from(linksOf(u, req).join('\n')).toString('base64'));
});

app.get('/health', (_, res) => res.send('ok'));
app.listen(PORT, () => console.log('PR Config running on :' + PORT));
