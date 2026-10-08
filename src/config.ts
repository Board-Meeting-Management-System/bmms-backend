const databaseUrl = process.env.CONTROL_DATABASE_URL;
if (!databaseUrl) throw new Error('CONTROL_DATABASE_URL is required');
const port = Number(process.env.PORT ?? 3001);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
export const config = {
  databaseUrl,
  port,
  host: process.env.HOST ?? '127.0.0.1',
  frontendOrigin: process.env.FRONTEND_ORIGIN ?? 'http://localhost:5173',
};
