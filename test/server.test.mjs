import test from 'node:test';
import { randomBytes } from 'node:crypto';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const ownerPassword = randomBytes(20).toString('hex');
function start(dataDir) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['server.mjs'], { cwd: root, env: { ...process.env, HOST: '127.0.0.1', PORT: '0', DATA_DIR: dataDir, NODE_ENV: 'test', PUBLIC_URL: '', RENDER_EXTERNAL_URL: '', ADMIN_PASSWORD: ownerPassword }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = ''; child.stderr.on('data', data => { stderr += data; }); child.once('error', reject);
    child.stdout.on('data', data => { stdout += data; const match = /listening on port (\d+)/.exec(stdout); if (match) resolve({ child, origin: 'http://127.0.0.1:' + match[1] }); });
    child.once('exit', code => { if (!/listening on port/.test(stdout)) reject(new Error(`Server exited ${code}: ${stderr}`)); });
  });
}
async function stop(child) { if (child.exitCode !== null) return; await new Promise(resolve => { child.once('exit', resolve); child.kill('SIGTERM'); }); }
function fixture() {
  return { version: 1, designRevision: 2, siteId: 'portfolio-studio-a82e1b', updatedAt: 1, texts: { 'text-8': '测试作者' }, settings: { pageWidth: 1280, spacing: 96, columns: 2, ratio: 1.5, fit: 'contain', heroRatio: 1, heroSize: 144, radius: 28, motion: true, paper: '#f1f7ff', ink: '#07182e', primary: '#36a7f8', primaryInk: '#185fe8', secondary: '#c8edff' }, sections: ['home','about','work','skills','contact'].map(id => ({ id, visible: true })), hero: { src: '', asset: 'mascot', alt: '角色' }, projects: [], skills: [], blocks: [], pages: [] };
}
test('authenticated online publishing, media, range requests and durable state', async t => {
  const dataDir = await mkdtemp(join(tmpdir(), 'portfolio-test-')); let running = await start(dataDir);
  t.after(async () => { await stop(running.child); await rm(dataDir, { recursive: true, force: true }); });
  let origin = running.origin, cookie, csrf;
  const request = (path, options = {}) => fetch(origin + path, options);
  const writeHeaders = () => ({ Origin: origin, Cookie: cookie, 'X-CSRF-Token': csrf, 'Content-Type': 'application/json', 'If-Match': '0' });
  await t.test('public HTML never exposes the server password verifier or private files', async () => {
    assert.equal((await request('/api/health')).status, 200);
    const html = await (await request('/')).text(); const raw = await readFile(join(root, 'index.html'), 'utf8'); const verifier = JSON.parse(/const AUTH = (\{[^;]+\});/.exec(raw)[1]);
    assert.ok(html.includes('portfolio-api')); assert.ok(html.includes('const AUTH = {serverManaged:true}')); assert.ok(!html.includes(verifier.hash));
    for (const path of ['/server.mjs','/.env','/.data/portfolio.sqlite','/server/owner-verifier.json']) assert.equal((await request(path)).status, 404);
    assert.equal((await request('/api/session')).status, 200);
  });
  await t.test('server authentication and CSRF/origin checks reject unauthorized writes', async () => {
    const body = JSON.stringify(fixture()); assert.equal((await request('/api/site', { method: 'PUT', headers: { Origin: origin, 'Content-Type': 'application/json' }, body })).status, 401);
    assert.equal((await request('/api/login', { method: 'POST', headers: { Origin: 'https://unrelated.example', 'Content-Type': 'application/json' }, body: JSON.stringify({ password: ownerPassword }) })).status, 403);
    assert.equal((await request('/api/login', { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: '{"password":"wrong"}' })).status, 401);
    const login = await request('/api/login', { method: 'POST', headers: { Origin: origin, 'Content-Type': 'application/json' }, body: JSON.stringify({ password: ownerPassword }) }); assert.equal(login.status, 200);
    cookie = login.headers.get('set-cookie').split(';')[0]; assert.match(login.headers.get('set-cookie'), /HttpOnly/); assert.match(login.headers.get('set-cookie'), /SameSite=Strict/); csrf = (await login.json()).csrf;
    const headers = writeHeaders(); delete headers['X-CSRF-Token']; assert.equal((await request('/api/site', { method: 'PUT', headers, body })).status, 403);
    assert.equal((await request('/api/site', { method: 'PUT', headers: { ...writeHeaders(), Origin: 'https://other.example' }, body })).status, 403);
  });
  let gif, video;
  await t.test('GIF uploads preserve original bytes, MP4 supports byte ranges and fake files are rejected', async () => {
    const bytes = Buffer.from('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7', 'base64');
    const response = await request('/api/media?name=sample.gif', { method: 'POST', headers: { Origin: origin, Cookie: cookie, 'X-CSRF-Token': csrf, 'Content-Type': 'image/gif' }, body: bytes }); assert.equal(response.status, 201); gif = await response.json(); assert.equal(gif.type, 'image/gif'); assert.deepEqual(Buffer.from(await (await request(gif.src)).arrayBuffer()), bytes);
    const mp4 = Buffer.concat([Buffer.from([0,0,0,24]), Buffer.from('ftypisom'), Buffer.from([0,0,2,0]), Buffer.from('isommp42'), Buffer.from('test-range-payload')]);
    const uploaded = await request('/api/media?name=video.mp4', { method: 'POST', headers: { Origin: origin, Cookie: cookie, 'X-CSRF-Token': csrf, 'Content-Type': 'video/mp4' }, body: mp4 }); assert.equal(uploaded.status, 201); video = await uploaded.json(); assert.equal(video.kind, 'video');
    const range = await request(video.src, { headers: { Range: 'bytes=0-9' } }); assert.equal(range.status, 206); assert.equal(range.headers.get('content-range'), `bytes 0-9/${mp4.length}`); assert.deepEqual(Buffer.from(await range.arrayBuffer()), mp4.subarray(0,10));
    const suffix = await request(video.src, { headers: { Range: 'bytes=-6' } }); assert.equal(suffix.status, 206); assert.deepEqual(Buffer.from(await suffix.arrayBuffer()), mp4.subarray(-6));
    assert.equal((await request(video.src, { headers: { Range: 'bytes=999999-' } })).status, 416);
    assert.equal((await request('/api/media', { method: 'POST', headers: { Origin: origin, Cookie: cookie, 'X-CSRF-Token': csrf, 'Content-Type': 'image/png' }, body: '<html>fake</html>' })).status, 415);
    assert.ok(!(await readdir(join(dataDir, 'uploads'))).some(name => name.endsWith('.tmp')));
  });
  let content;
  await t.test('page contents publish to other visitors, invalid states and stale revisions are rejected', async () => {
    content = fixture(); content.pages = [{ id: 'page-one', slug: 'motion-work', title: '动态设计', description: '介绍', visible: true, layout: 'grid', blocks: [{ id: 'gif', kind: 'media', media: gif }, { id: 'video', kind: 'media', media: video }] }];
    const saved = await request('/api/site', { method: 'PUT', headers: writeHeaders(), body: JSON.stringify(content) }); assert.equal(saved.status, 200); assert.equal((await saved.json()).revision, 1);
    const publicState = await (await request('/api/site')).json(); assert.equal(publicState.state.pages[0].slug, 'motion-work'); assert.equal(publicState.state.pages[0].blocks[1].media.type, 'video/mp4');
    assert.equal((await request('/p/motion-work')).status, 200); assert.equal((await request('/p/does-not-exist')).status, 404);
    assert.equal((await request('/api/site', { method: 'PUT', headers: writeHeaders(), body: JSON.stringify(content) })).status, 409);
    const unsafe = structuredClone(content); unsafe.pages[0].slug = '../private'; assert.equal((await request('/api/site', { method: 'PUT', headers: { ...writeHeaders(), 'If-Match': '1' }, body: JSON.stringify(unsafe) })).status, 400);
    unsafe.pages[0].slug = 'valid'; unsafe.pages[0].blocks[0].media.src = 'javascript:alert(1)'; assert.equal((await request('/api/site', { method: 'PUT', headers: { ...writeHeaders(), 'If-Match': '1' }, body: JSON.stringify(unsafe) })).status, 400);
  });
  await t.test('database and uploads survive a server restart, logout invalidates the session', async () => {
    await stop(running.child); running = await start(dataDir); origin = running.origin;
    const saved = await (await request('/api/site')).json(); assert.equal(saved.revision, 1); assert.equal(saved.state.texts['text-8'], '测试作者'); assert.equal((await request(gif.src)).status, 200);
    const current = await (await request('/api/session', { headers: { Cookie: cookie } })).json(); assert.equal(current.authenticated, true);
    assert.equal((await request('/api/logout', { method: 'POST', headers: writeHeaders() })).status, 200);
    assert.equal((await (await request('/api/session', { headers: { Cookie: cookie } })).json()).authenticated, false);
    assert.equal((await request('/api/site', { method: 'PUT', headers: { ...writeHeaders(), 'If-Match': '1' }, body: JSON.stringify(content) })).status, 401);
  });
});
