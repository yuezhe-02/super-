import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { mkdir, readFile, rename, rm, stat } from 'node:fs/promises';
import { createReadStream, createWriteStream } from 'node:fs';
import { randomBytes, randomUUID, createHash, pbkdf2, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { validateSite, sniffMedia, SiteError } from './server/schema.mjs';
const root = dirname(fileURLToPath(import.meta.url));
const dataDir = resolve(process.env.DATA_DIR || join(root, '.data'));
await mkdir(join(dataDir, 'uploads'), { recursive: true });
const db = new DatabaseSync(join(dataDir, 'portfolio.sqlite'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;
 CREATE TABLE IF NOT EXISTS site(id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL, content TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, csrf TEXT NOT NULL, expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS owner(id INTEGER PRIMARY KEY CHECK(id=1), salt TEXT NOT NULL, hash TEXT NOT NULL, iterations INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS media(id TEXT PRIMARY KEY, filename TEXT UNIQUE NOT NULL, type TEXT NOT NULL, size INTEGER NOT NULL, created INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS attempts(address TEXT PRIMARY KEY, failures INTEGER NOT NULL, reset INTEGER NOT NULL);`);
const derive = promisify(pbkdf2), hash = value => createHash('sha256').update(value).digest('hex');
const source = await readFile(join(root, 'index.html'), 'utf8');
const browserHTML = source.replace(/const AUTH = \{[^;]+\};/, 'const AUTH = {serverManaged:true};').replace('<head>', '<head>\n<meta name="portfolio-api" content="1">');
const configuredURL = process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || '';
if (configuredURL && !/^https?:\/\//.test(configuredURL)) throw new Error('PUBLIC_URL must be an HTTP(S) origin');
const fixedOrigin = configuredURL ? new URL(configuredURL).origin : null;
const secureCookies = process.env.NODE_ENV === 'production' || configuredURL.startsWith('https:');
const mediaLimit = Number(process.env.MAX_UPLOAD_MB || 100) * 1024 * 1024;
if (!Number.isFinite(mediaLimit) || mediaLimit < 1024 || mediaLimit > 1024 ** 3) throw new Error('Invalid MAX_UPLOAD_MB');
const existingOwner = db.prepare('SELECT * FROM owner WHERE id=1').get();
let passwordChanged = false;
if (process.env.ADMIN_PASSWORD && existingOwner) { const candidate = await derive(process.env.ADMIN_PASSWORD, Buffer.from(existingOwner.salt, 'hex'), existingOwner.iterations, 32, 'sha256'); passwordChanged = !timingSafeEqual(candidate, Buffer.from(existingOwner.hash, 'hex')); }
if (!existingOwner || passwordChanged) {
  let verifier;
  if (process.env.ADMIN_PASSWORD) { const salt = randomBytes(16); verifier = { salt: salt.toString('hex'), hash: (await derive(process.env.ADMIN_PASSWORD, salt, 600000, 32, 'sha256')).toString('hex'), iterations: 600000 }; db.prepare('DELETE FROM sessions').run(); }
  else {
    if (process.env.NODE_ENV === 'production') throw new Error('Set ADMIN_PASSWORD in hosting environment settings before first production start');
    verifier = JSON.parse(/const AUTH = (\{[^;]+\});/.exec(source)[1]);
  }
  db.prepare('INSERT OR REPLACE INTO owner VALUES(1,?,?,?)').run(verifier.salt, verifier.hash, verifier.iterations);
}
const defaultHeaders = { 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'Cross-Origin-Resource-Policy': 'same-origin', 'X-Frame-Options': 'DENY' };
function send(res, status, value, extra = {}) { const body = Buffer.from(JSON.stringify(value)); res.writeHead(status, { ...defaultHeaders, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': body.length, ...extra }); res.end(body); }
function session(req) { const raw = /(?:^|;\s*)portfolio_session=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie || '')?.[1]; if (!raw) return null; return db.prepare('SELECT * FROM sessions WHERE token=? AND expires>?').get(hash(raw), Date.now()) || null; }
function requireOwner(req) { const current = session(req); if (!current) throw new SiteError('请先登录管理账号', 401); return current; }
function requireOrigin(req) { const expected = fixedOrigin || `http${secureCookies ? 's' : ''}://${req.headers.host}`; if (req.headers.origin !== expected || req.headers['sec-fetch-site'] === 'cross-site') throw new SiteError('请求来源不匹配', 403); }
function requireWrite(req) { requireOrigin(req); const current = requireOwner(req); if (req.headers['x-csrf-token'] !== current.csrf) throw new SiteError('登录校验已失效，请重新登录', 403); return current; }
async function readJSON(req, limit = 12 * 1024 * 1024) { if (!/^application\/json(?:;|$)/i.test(req.headers['content-type'] || '')) throw new SiteError('需要 JSON 请求', 415); const parts = []; let size = 0; for await (const chunk of req) { size += chunk.length; if (size > limit) throw new SiteError('内容过大，请先单独上传媒体文件', 413); parts.push(chunk); } try { return JSON.parse(Buffer.concat(parts).toString('utf8')); } catch { throw new SiteError('JSON 格式错误'); } }
const cookie = (token, age) => `portfolio_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${secureCookies ? '; Secure' : ''}`;
async function upload(req, res, url) {
  requireWrite(req); const type = (req.headers['content-type'] || '').split(';')[0];
  if (!['image/png','image/jpeg','image/gif','image/webp','image/avif','video/mp4','video/webm'].includes(type)) throw new SiteError('不支持的媒体类型', 415);
  if (Number(req.headers['content-length']) > mediaLimit) throw new SiteError('文件超过上传大小限制', 413);
  const id = randomUUID(), temporary = join(dataDir, 'uploads', `${id}.tmp`); let bytes = 0, prefix = Buffer.alloc(0);
  const limiter = new Transform({ transform(chunk, _, done) { bytes += chunk.length; if (bytes > mediaLimit) return done(new SiteError('文件超过上传大小限制', 413)); if (prefix.length < 64) prefix = Buffer.concat([prefix, chunk.subarray(0, 64 - prefix.length)]); done(null, chunk); } });
  try {
    await pipeline(req, limiter, createWriteStream(temporary, { flags: 'wx', mode: 0o600 }));
    const format = sniffMedia(prefix, type), filename = `${id}.${format.extension}`;
    await rename(temporary, join(dataDir, 'uploads', filename));
    try { db.prepare('INSERT INTO media VALUES(?,?,?,?,?)').run(id, filename, type, bytes, Date.now()); } catch (error) { await rm(join(dataDir, 'uploads', filename), { force: true }); throw error; }
    send(res, 201, { id, src: `/media/${filename}`, asset: '', kind: format.kind, type, size: bytes, alt: (url.searchParams.get('name') || '新媒体').slice(0, 200) });
  } catch (error) { await rm(temporary, { force: true }); throw error; }
}
async function serveMedia(req, res, pathname) {
  const filename = pathname.slice('/media/'.length); if (!/^[a-f0-9-]{36}\.(?:png|jpg|webp|gif|avif|mp4|webm)$/.test(filename)) throw new SiteError('文件不存在', 404);
  const row = db.prepare('SELECT * FROM media WHERE filename=?').get(filename); if (!row) throw new SiteError('文件不存在', 404);
  const path = join(dataDir, 'uploads', filename), info = await stat(path); let start = 0, end = info.size - 1, status = 200;
  const headers = { ...defaultHeaders, 'Content-Type': row.type, 'Cache-Control': 'public, max-age=31536000, immutable', 'Accept-Ranges': 'bytes' };
  if (req.headers.range) {
    const range = /^bytes=(\d*)-(\d*)$/.exec(req.headers.range);
    if (!range || (!range[1] && !range[2])) { res.writeHead(416, { ...headers, 'Content-Range': `bytes */${info.size}` }); return res.end(); }
    if (!range[1]) { const length = Number(range[2]); if (!length) throw new SiteError('无效 Range', 416); start = Math.max(0, info.size - length); } else { start = Number(range[1]); if (range[2]) end = Math.min(end, Number(range[2])); }
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start > end || start >= info.size) { res.writeHead(416, { ...headers, 'Content-Range': `bytes */${info.size}` }); return res.end(); }
    status = 206; headers['Content-Range'] = `bytes ${start}-${end}/${info.size}`;
  }
  res.writeHead(status, { ...headers, 'Content-Length': end - start + 1 }); if (req.method === 'HEAD') return res.end(); await pipeline(createReadStream(path, { start, end }), res);
}
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/api/health' && req.method === 'GET') return send(res, 200, { ok: true });
    if (url.pathname === '/api/session' && req.method === 'GET') { const current = session(req); return send(res, 200, { authenticated: !!current, csrf: current?.csrf || null }); }
    if (url.pathname === '/api/login' && req.method === 'POST') {
      requireOrigin(req); const body = await readJSON(req, 2048), address = req.socket.remoteAddress || 'unknown'; const now = Date.now(), attempt = db.prepare('SELECT * FROM attempts WHERE address=?').get(address);
      if (attempt && attempt.failures >= 10 && attempt.reset > now) throw new SiteError('尝试次数较多，请 15 分钟后重试', 429);
      if (typeof body.password !== 'string' || body.password.length > 128) throw new SiteError('密码不正确', 401);
      const owner = db.prepare('SELECT * FROM owner WHERE id=1').get(); const actual = await derive(body.password, Buffer.from(owner.salt, 'hex'), owner.iterations, 32, 'sha256');
      if (!timingSafeEqual(actual, Buffer.from(owner.hash, 'hex'))) { db.prepare('INSERT OR REPLACE INTO attempts VALUES(?,?,?)').run(address, attempt && attempt.reset > now ? attempt.failures + 1 : 1, now + 15 * 60000); throw new SiteError('密码不正确', 401); }
      db.prepare('DELETE FROM attempts WHERE address=?').run(address); db.prepare('DELETE FROM sessions WHERE expires<?').run(now);
      const old = session(req); if (old) db.prepare('DELETE FROM sessions WHERE token=?').run(old.token);
      const token = randomBytes(32).toString('hex'), csrf = randomBytes(24).toString('hex'); db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(hash(token), csrf, now + 8 * 3600000);
      return send(res, 200, { authenticated: true, csrf }, { 'Set-Cookie': cookie(token, 8 * 3600) });
    }
    if (url.pathname === '/api/logout' && req.method === 'POST') { const current = requireWrite(req); db.prepare('DELETE FROM sessions WHERE token=?').run(current.token); return send(res, 200, { ok: true }, { 'Set-Cookie': cookie('', 0) }); }
    if (url.pathname === '/api/site' && req.method === 'GET') { const row = db.prepare('SELECT * FROM site WHERE id=1').get(); return send(res, 200, { revision: row?.revision || 0, state: row ? JSON.parse(row.content) : null }); }
    if (url.pathname === '/api/site' && req.method === 'PUT') {
      requireWrite(req); const content = validateSite(await readJSON(req), src => !!db.prepare('SELECT id FROM media WHERE filename=?').get(src.slice(7))); const expected = Number(req.headers['if-match']); if (!Number.isSafeInteger(expected)) throw new SiteError('缺少内容版本', 428);
      db.exec('BEGIN IMMEDIATE'); let revision;
      try { const row = db.prepare('SELECT revision FROM site WHERE id=1').get(); if ((row?.revision || 0) !== expected) throw new SiteError('网站已在其他窗口修改，请备份当前内容后刷新再编辑', 409); revision = expected + 1; db.prepare('INSERT OR REPLACE INTO site VALUES(1,?,?)').run(revision, JSON.stringify(content)); db.exec('COMMIT'); } catch (error) { db.exec('ROLLBACK'); throw error; }
      return send(res, 200, { revision, updatedAt: content.updatedAt });
    }
    if (url.pathname === '/api/media' && req.method === 'POST') return await upload(req, res, url);
    if (url.pathname.startsWith('/media/') && ['GET','HEAD'].includes(req.method)) return await serveMedia(req, res, url.pathname);
    if (['GET','HEAD'].includes(req.method) && (['/','/index.html'].includes(url.pathname) || /^\/p\/[a-z0-9][a-z0-9-]{0,59}$/.test(url.pathname))) {
      const slug = /^\/p\/([a-z0-9][a-z0-9-]{0,59})$/.exec(url.pathname)?.[1];
      if (slug) { const row = db.prepare('SELECT content FROM site WHERE id=1').get(); const page = row && JSON.parse(row.content).pages?.find(p => p.slug === slug && p.visible); if (!page && !session(req)) { res.writeHead(404, { ...defaultHeaders, 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }); return res.end(req.method === 'HEAD' ? undefined : browserHTML); } }
      const body = Buffer.from(browserHTML); res.writeHead(200, { ...defaultHeaders, 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache', 'Content-Length': body.length, 'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' data: blob:; connect-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" }); return res.end(req.method === 'HEAD' ? undefined : body);
    }
    if (url.pathname === '/favicon.ico' && req.method === 'GET') { res.writeHead(204); return res.end(); }
    throw new SiteError('页面不存在', 404);
  } catch (error) { if (res.headersSent || res.destroyed) return; send(res, error.status || 500, { error: error.status ? error.message : '服务暂时不可用，请稍后重试' }); }
});
server.requestTimeout = 5 * 60000;
server.listen(Number(process.env.PORT || 3000), process.env.HOST || '0.0.0.0', () => console.log(`Portfolio server listening on port ${server.address().port}`));
function shutdown() { server.close(() => { db.close(); process.exit(0); }); }
process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown);
