import { buildApp } from './app.js';
import { config } from './config.js';
const app = await buildApp();
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.once(signal, () => { void app.close(); });
}
try { 
  await app.listen({ 
    host: config.host, 
    port: config.port 
  }); 
}catch { 
  console.error('API startup failed; check port and configuration'); 
  await app.close(); process.exitCode = 1; 
}
