import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import pg from 'pg';

const pool = new pg.Pool({
  host: 'db', database: 'demo', user: 'demo',
  password: (await readFile('/run/secrets/db_password', 'utf8')).trim(),
  connectionTimeoutMillis: 2000, query_timeout: 2000, max: 4,
});
const page = await readFile(new URL('./index.html', import.meta.url));
const node = process.env.SITE_LABEL || 'SITE';
const version = process.env.APP_VERSION || '0.0.1';
const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'");
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { Allow: 'GET, HEAD' }); return res.end();
  }
  try {
    if (req.url === '/api/status' || req.url === '/healthz') {
      const { rows } = await pool.query('SELECT id, message, attachment_sha256 FROM demo_records ORDER BY id');
      const file = await readFile('/data/recovery-proof.txt');
      const fileSha = createHash('sha256').update(file).digest('hex');
      const consistent = rows.length > 0 && rows.every(row => row.attachment_sha256 === fileSha);
      res.writeHead(consistent ? 200 : 503, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ node, version, healthy: consistent, records: rows,
        attachmentSha256: fileSha, checkedAt: new Date().toISOString() }));
    }
    if (req.url === '/' || req.url === '/index.html') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(req.method === 'HEAD' ? undefined : page);
    }
    res.writeHead(404); res.end('Not found');
  } catch {
    res.writeHead(503, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ node, version, healthy: false, error: 'Data verification unavailable' }));
  }
});
server.listen(8080, '0.0.0.0');
process.on('SIGTERM', () => server.close(() => pool.end().then(() => process.exit(0)))) ;
