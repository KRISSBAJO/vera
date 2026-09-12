#!/usr/bin/env node
/**
 * Serves the landing page locally.
 *
 * Deliberately separate from the dashboard. They are different products for different audiences: the
 * landing page is read by people who do not have an account, the dashboard by reviewers who do. In
 * production they are different hosts (vera.example for one, app.vera.example for the other), and a
 * marketing page that can only be reached through an app's auth middleware is the wrong shape.
 *
 * No dependencies and no build step — it is one static file, and that is the point.
 */
import { createReadStream, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
const port = Number(process.env.PORT ?? 4200);

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
};

createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://localhost');
  // normalize() collapses `..`, so a request for /../../.env cannot escape this directory.
  const rel = normalize(decodeURIComponent(url.pathname)).replace(/^(\.\.[/\\])+/, '');
  const path = join(root, rel === '/' || rel === '\\' ? 'index.html' : rel);

  if (!path.startsWith(root)) {
    res.writeHead(403).end('forbidden');
    return;
  }
  try {
    if (!statSync(path).isFile()) throw new Error('not a file');
  } catch {
    res.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
    return;
  }
  res.writeHead(200, {
    'content-type': TYPES[extname(path)] ?? 'application/octet-stream',
    'cache-control': 'no-store',
  });
  createReadStream(path).pipe(res);
}).listen(port, () => {
  console.log(`\n  VERA landing page → http://localhost:${port}\n`);
});
