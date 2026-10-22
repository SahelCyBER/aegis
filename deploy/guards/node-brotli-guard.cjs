'use strict';
/*
 * AEGIS virtual patch for CVE-2026-111497 (Node.js Brotli decoder OOB write -> RCE).
 *
 * Load it in every Node process until the runtime is upgraded to a fixed release
 * (22.23.4 / 24.22.1 / 26.12.1; 20.x is EOL and gets no fix):
 *
 *     NODE_OPTIONS="--require /path/to/node-brotli-guard.cjs"
 *
 * What it does (no dependency, no config):
 *   1. Brotli DECOMPRESSION is refused: zlib.createBrotliDecompress,
 *      brotliDecompress and brotliDecompressSync throw / error. Untrusted Brotli
 *      input never reaches the vulnerable decoder. Compression is untouched.
 *   2. Outbound fetch() stops advertising Brotli: requests without an explicit
 *      Accept-Encoding get "gzip, deflate", so well-behaved servers never answer
 *      with br. A malicious server that sends br anyway hits (1) and the request
 *      fails instead of decoding the payload.
 *   3. Incoming HTTP requests with Content-Encoding: br are answered 415 before
 *      any body parser can inflate them.
 * Set AEGIS_BROTLI_GUARD=off to disable without removing the preload.
 */
if (process.env.AEGIS_BROTLI_GUARD === 'off') return;

const zlib = require('zlib');
const http = require('http');

const MSG = 'Brotli decompression disabled by AEGIS guard (CVE-2026-111497); upgrade Node.js';
function refused() { const e = new Error(MSG); e.code = 'ERR_AEGIS_BROTLI_DISABLED'; return e; }

// zlib exports are non-writable but configurable: redefine instead of assigning.
function override(obj, name, fn) {
  Object.defineProperty(obj, name, { value: fn, writable: true, configurable: true, enumerable: true });
}
const asyncRefuse = function (_buf, opts, cb) {
  if (typeof opts === 'function') cb = opts;
  if (typeof cb === 'function') { process.nextTick(cb, refused()); return; }
  throw refused();
};
try { asyncRefuse[require('util').promisify.custom] = () => Promise.reject(refused()); } catch (_) {}
// Return a stream that fails instead of throwing: undici (fetch) calls this from
// its header parser, where a synchronous throw would crash the process. An
// erroring stream makes the fetch reject cleanly and decodes nothing.
const { Transform } = require('stream');
override(zlib, 'createBrotliDecompress', function () {
  const t = new Transform({ transform(_chunk, _enc, cb) { cb(refused()); } });
  process.nextTick(() => t.destroy(refused()));
  return t;
});
override(zlib, 'brotliDecompressSync', function () { throw refused(); });
override(zlib, 'brotliDecompress', asyncRefuse);
// The class is also reachable as zlib.BrotliDecompress (new zlib.BrotliDecompress()).
override(zlib, 'BrotliDecompress', function BrotliDecompress() { throw refused(); });

if (typeof globalThis.fetch === 'function') {
  const origFetch = globalThis.fetch;
  globalThis.fetch = function guardedFetch(input, init) {
    try {
      const headers = new Headers((init && init.headers) || (input && typeof input === 'object' && input.headers) || undefined);
      if (!headers.has('accept-encoding')) {
        headers.set('accept-encoding', 'gzip, deflate');
        init = Object.assign({}, init, { headers });
      }
    } catch (_) {}
    return origFetch.call(this, input, init);
  };
}

const origEmit = http.Server.prototype.emit;
http.Server.prototype.emit = function (event, req, res) {
  if (event === 'request' && req && req.headers) {
    const ce = String(req.headers['content-encoding'] || '').toLowerCase();
    if (ce.split(',').some((v) => v.trim() === 'br')) {
      try {
        res.statusCode = 415;
        res.setHeader('content-type', 'text/plain');
        res.end('Content-Encoding br not accepted\n');
        req.resume();
      } catch (_) {}
      try { process.emitWarning(`[aegis-guard] rejected Content-Encoding: br from ${req.socket && req.socket.remoteAddress} ${req.method} ${req.url}`); } catch (_) {}
      return true;
    }
  }
  return origEmit.apply(this, arguments);
};

process.emitWarning('[aegis-guard] CVE-2026-111497 Brotli guard active', { code: 'AEGIS_BROTLI_GUARD' });
