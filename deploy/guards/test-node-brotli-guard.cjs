'use strict';
// Self-contained check for node-brotli-guard.cjs. Run with:
//   NODE_OPTIONS="--require ./deploy/guards/node-brotli-guard.cjs" node deploy/guards/test-node-brotli-guard.cjs
const http = require('http');
const https = require('https');
const http2 = require('http2');
const zlib = require('zlib');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

let pass = 0, fail = 0, skip = 0;
function report(name, ok, extra) {
  if (ok) pass++; else fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${!ok && extra ? ' -> ' + extra : ''}`);
}
function skipped(name, why) { skip++; console.log(`SKIP ${name} (${why})`); }
const withTimeout = (p, ms = 5000) => Promise.race([p, new Promise((_, rj) => setTimeout(() => rj(new Error('timeout')), ms))]);

// ---- TLS material (openssl), optional
let tmp, tls = null;
try {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'brguard-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-days', '1',
    '-keyout', path.join(tmp, 'k.pem'), '-out', path.join(tmp, 'c.pem')], { stdio: 'ignore' });
  tls = { key: fs.readFileSync(path.join(tmp, 'k.pem')), cert: fs.readFileSync(path.join(tmp, 'c.pem')) };
} catch (_) { tls = null; }

// ---- servers: each counts how many requests reached the app
const hits = {};
function listen(name, server) {
  hits[name] = 0;
  return new Promise((res) => server.listen(0, '127.0.0.1', () => res({ name, server, port: server.address().port })));
}
const httpHandler = (name) => (req, res) => {
  hits[name]++;
  if (req.url === '/ae') { res.end(String(req.headers['accept-encoding'])); return; }
  req.resume(); req.on('end', () => res.end('ok'));
};
const compat = (name) => (req, res) => { hits[name]++; req.resume(); req.on('end', () => res.end('ok')); };
const streamH = (name) => (stream) => { hits[name]++; stream.resume(); stream.respond({ ':status': 200 }); stream.end('ok'); };

// ---- clients: resolve to HTTP status
function h1(mod, port, headers) {
  return new Promise((resolve, reject) => {
    const req = mod.request({ host: '127.0.0.1', port, method: 'POST', path: '/', headers, rejectUnauthorized: false }, (res) => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
    req.end('xxxxxxxx');
  });
}
function h2(scheme, port, headers) {
  return new Promise((resolve, reject) => {
    const c = http2.connect(`${scheme}://127.0.0.1:${port}`, { rejectUnauthorized: false });
    c.on('error', reject);
    const req = c.request(Object.assign({ ':method': 'POST', ':path': '/' }, headers));
    let status;
    req.on('response', (h) => { status = h[':status']; });
    req.on('error', reject);
    req.resume();
    req.on('end', () => { c.close(); resolve(status); });
    req.end('xxxxxxxx');
  });
}

const BR_VARIANTS = [
  ['br', { 'content-encoding': 'br' }],
  ['BR', { 'content-encoding': 'BR' }],
  [' br', { 'content-encoding': ' br' }],
  ['gzip, br', { 'content-encoding': 'gzip, br' }],
  ['gzip,BR ;q=0.5', { 'content-encoding': 'gzip,BR ;q=0.5' }],
  ['array [gzip, br]', { 'content-encoding': ['gzip', 'br'] }],
];
const OK_VARIANTS = [
  ['no header', {}],
  ['gzip', { 'content-encoding': 'gzip' }],
  ['brotli (not br)', { 'content-encoding': 'brotli' }],
];

// The Node HTTP/2 client drops a header with leading whitespace and rejects array
// values, so those two variants are only sent over HTTP/1.
const H1_ONLY = new Set([' br', 'array [gzip, br]']);
async function matrix(label, name, call, isH2) {
  for (const [v, h] of BR_VARIANTS) {
    if (isH2 && H1_ONLY.has(v)) continue;
    const before = hits[name];
    let st; try { st = await withTimeout(call(h)); } catch (e) { st = 'err:' + e.message; }
    report(`${label} Content-Encoding ${v} -> 415, not delivered`, st === 415 && hits[name] === before, `status=${st} delivered=${hits[name] - before}`);
  }
  for (const [v, h] of OK_VARIANTS) {
    let st; try { st = await withTimeout(call(h)); } catch (e) { st = 'err:' + e.message; }
    report(`${label} normal POST (${v}) -> 200`, st === 200, `status=${st}`);
  }
}

(async () => {
  const servers = [];
  const s_http = await listen('http', http.createServer(httpHandler('http'))); servers.push(s_http);
  await matrix('http', 'http', (h) => h1(http, s_http.port, h));

  if (tls) {
    const s = await listen('https', https.createServer(tls, httpHandler('https'))); servers.push(s);
    await matrix('https', 'https', (h) => h1(https, s.port, h));
  } else skipped('https cases', 'openssl missing');

  const c1 = http2.createServer(); c1.on('request', compat('h2c-compat'));
  const s_c1 = await listen('h2c-compat', c1); servers.push(s_c1);
  await matrix('h2c compat', 'h2c-compat', (h) => h2('http', s_c1.port, h), true);

  const c2 = http2.createServer(); c2.on('stream', streamH('h2c-stream'));
  const s_c2 = await listen('h2c-stream', c2); servers.push(s_c2);
  await matrix('h2c stream', 'h2c-stream', (h) => h2('http', s_c2.port, h), true);

  if (tls) {
    const t1 = http2.createSecureServer(tls); t1.on('request', compat('h2s-compat'));
    const s_t1 = await listen('h2s-compat', t1); servers.push(s_t1);
    await matrix('h2 secure compat', 'h2s-compat', (h) => h2('https', s_t1.port, h), true);

    const t2 = http2.createSecureServer(tls); t2.on('stream', streamH('h2s-stream'));
    const s_t2 = await listen('h2s-stream', t2); servers.push(s_t2);
    await matrix('h2 secure stream', 'h2s-stream', (h) => h2('https', s_t2.port, h), true);
  } else skipped('http2 secure cases', 'openssl missing');

  // ---- existing behaviours
  try { zlib.brotliDecompressSync(zlib.brotliCompressSync('hello')); report('zlib.brotliDecompressSync refused', false, 'did not throw'); }
  catch (e) { report('zlib.brotliDecompressSync refused', e.code === 'ERR_AEGIS_BROTLI_DISABLED', e.message); }
  report('zlib.brotliDecompress (callback) refused', await new Promise((res) => {
    try { zlib.brotliDecompress(Buffer.from('x'), (err) => res(!!err && err.code === 'ERR_AEGIS_BROTLI_DISABLED')); } catch (e) { res(e.code === 'ERR_AEGIS_BROTLI_DISABLED'); }
  }));
  report('zlib.createBrotliDecompress stream errors', await withTimeout(new Promise((res) => {
    const s = zlib.createBrotliDecompress(); s.on('error', (e) => res(e.code === 'ERR_AEGIS_BROTLI_DISABLED')); s.on('data', () => {}); s.end(Buffer.from('x'));
  }), 3000).catch(() => false));
  let compressed = null;
  try { compressed = zlib.brotliCompressSync('hello'); } catch (_) {}
  report('brotli compression still works', !!compressed && compressed.length > 0);
  report('gzip roundtrip works', zlib.gunzipSync(zlib.gzipSync('hello')).toString() === 'hello');

  const ae = await new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: s_http.port, path: '/ae', headers: { 'Accept-Encoding': 'gzip, deflate, br' } }, (r) => {
      let d = ''; r.on('data', (c) => d += c); r.on('end', () => resolve(d));
    }).on('error', reject);
  }).catch((e) => 'err:' + e.message);
  report('outbound http Accept-Encoding without br', !/\bbr\b/i.test(ae) && /gzip/.test(ae), `sent=${ae}`);
  if (typeof fetch === 'function') {
    const fae = await withTimeout(fetch(`http://127.0.0.1:${s_http.port}/ae`).then((r) => r.text())).catch((e) => 'err:' + e.message);
    report('outbound fetch Accept-Encoding without br', !/\bbr\b/i.test(fae) && /gzip/.test(fae), `sent=${fae}`);
  } else skipped('fetch check', 'no global fetch');

  for (const s of servers) { try { s.server.close(); if (s.server.closeAllConnections) s.server.closeAllConnections(); } catch (_) {} }
  try { tmp && fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
  console.log(`\nnode ${process.version}: ${pass} PASS, ${fail} FAIL, ${skip} SKIP`);
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.log('FAIL harness ->', e && e.stack || e); process.exit(1); });
