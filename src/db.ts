import pg from 'pg';
import { config } from './config.js';
export const pool = new pg.Pool({ connectionString: config.databaseUrl, max: 5, connectionTimeoutMillis: 3000 });
pool.on('error', () => console.error('Idle database connection failed'));
