import { readdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { pool } from './db.js';
const client = await pool.connect();
try {
  await client.query('SELECT pg_advisory_lock(732104)');
  await client.query('CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())');
  const folder = resolve('migrations/control');
  for (const name of (await readdir(folder)).filter(n => n.endsWith('.sql')).sort()) {
    const sql = await readFile(resolve(folder, name), 'utf8');
    const checksum = createHash('sha256').update(sql).digest('hex');
    const previous = await client.query('SELECT checksum FROM schema_migrations WHERE name=$1', [name]);
    if (previous.rowCount) {
      if (previous.rows[0].checksum !== checksum) throw new Error('Applied migration was changed: ' + name);
      continue;
    }
    await client.query('BEGIN');
    try {
      await client.query(sql);
      await client.query('INSERT INTO schema_migrations(name, checksum) VALUES ($1,$2)', [name, checksum]);
      await client.query('COMMIT');
      console.log('Applied', name);
    } catch (error) { await client.query('ROLLBACK'); throw error; }
  }
} finally {
  try { await client.query('SELECT pg_advisory_unlock(732104)'); }
  finally { client.release(); await pool.end(); }
}
