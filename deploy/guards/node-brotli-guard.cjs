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
 *   3. Outbound http/https requests (axios, got...) have br stripped from
 *      Accept-Encoding, so they keep working against servers that support it.
 *   4. Incoming requests with Content-Encoding: br are answered 415 before any body
 *      parser can inflate them (http, https and http2, compat and stream APIs).
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

// Outbound http/https (axios, got, node-fetch...): strip "br" from any
// Accept-Encoding the library sets, so servers answer gzip/deflate instead of
// Brotli and the request keeps working. A server that sends br anyway hits the
// refused decoder above and that request fails cleanly.
function stripBr(value) {
  if (value == null) return value;
  const parts = String(value).split(',').map((v) => v.trim()).filter((v) => v && !/^br(\s*;.*)?$/i.test(v));
  return parts.length ? parts.join(', ') : 'identity';
}
function fixHeaders(h) {
  if (!h || typeof h !== 'object') return;
  for (const k of Object.keys(h)) if (k.toLowerCase() === 'accept-encoding') h[k] = stripBr(h[k]);
}
const https = require('https');
for (const mod of [http, https]) {
  for (const fn of ['request', 'get']) {
    const orig = mod[fn];
    const wrapped = function (...args) {
      for (const a of args) if (a && typeof a === 'object' && !(a instanceof URL)) fixHeaders(a.headers);
      return orig.apply(this, args);
    };
    try { override(mod, fn, wrapped); } catch (_) { try { mod[fn] = wrapped; } catch (_) {} }
  }
}
const origSetHeader = http.ClientRequest.prototype.setHeader;
http.ClientRequest.prototype.setHeader = function (name, value) {
  if (typeof name === 'string' && name.toLowerCase() === 'accept-encoding') value = stripBr(value);
  return origSetHeader.call(this, name, value);
};

// Incoming requests: true if any listed Content-Encoding coding is "br". Accepts a
// string or an array of header values, any case, optional whitespace and q-params.
function hasBr(value) {
  if (value == null) return false;
  const list = Array.isArray(value) ? value.join(',') : String(value);
  return list.split(',').some((v) => v.split(';')[0].trim().toLowerCase() === 'br');
}
function warnRejected(what) {
  try { process.emitWarning(`[aegis-guard] rejected Content-Encoding: br from ${what}`); } catch (_) {}
}

const GUARDED = Symbol.for('aegis.brotliGuard.emit');
function patchEmit(proto) {
  if (!proto || typeof proto.emit !== 'function' || proto.emit[GUARDED]) return;
  const origEmit = proto.emit;
  const guarded = function (event, a, b) {
    if (event === 'request' && a && a.headers && hasBr(a.headers['content-encoding'])) {
      // HTTP/1 and the HTTP/2 compatibility API: (req, res)
      try {
        b.statusCode = 415;
        b.setHeader('content-type', 'text/plain');
        b.end('Content-Encoding br not accepted\n');
        a.resume();
      } catch (_) {}
      warnRejected(`${a.socket && a.socket.remoteAddress} ${a.method} ${a.url}`);
      return true;
    }
    if (event === 'stream' && b && hasBr(b['content-encoding'])) {
      // HTTP/2 core API: (stream, headers). Also runs before the compat layer.
      try {
        a.respond({ ':status': 415, 'content-type': 'text/plain' });
        a.end('Content-Encoding br not accepted\n');
        a.resume();
      } catch (_) {}
      warnRejected(`${a.session && a.session.socket && a.session.socket.remoteAddress} ${b[':method']} ${b[':path']}`);
      return true;
    }
    return origEmit.apply(this, arguments);
  };
  guarded[GUARDED] = true;
  proto.emit = guarded;
}

// https.Server inherits from tls.Server, not http.Server: patch it on its own
// (patchEmit skips it if it already resolves to a guarded emit).
patchEmit(http.Server.prototype);
patchEmit(https.Server.prototype);

// http2: reach the server classes through throwaway instances (never listening).
try {
  const http2 = require('http2');
  for (const make of ['createServer', 'createSecureServer']) {
    let inst;
    try {
      inst = http2[make]();
      patchEmit(Object.getPrototypeOf(inst));
    } catch (_) {
      // Could not build the class by hand (e.g. createSecureServer needs options):
      // patch each instance the app creates instead.
      const orig = http2[make];
      const wrapped = function (...args) {
        const s = orig.apply(this, args);
        if (s && !s.emit[GUARDED]) {
          const proto = Object.getPrototypeOf(s);
          if (proto) patchEmit(proto);
        }
        return s;
      };
      try { override(http2, make, wrapped); } catch (_) {}
    } finally {
      try { inst && inst.close(); } catch (_) {}
    }
  }
} catch (_) {}

process.emitWarning('[aegis-guard] CVE-2026-111497 Brotli guard active', { code: 'AEGIS_BROTLI_GUARD' });
