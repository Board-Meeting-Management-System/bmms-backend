import Fastify from 'fastify';
import cors from '@fastify/cors';
import rateLimit from "@fastify/rate-limit"
import { config } from './config.js';
import { pool } from './db.js';
import { browserAuthRoutes } from './modules/auth/browser-auth.routes.js';
import { authRoutes } from './modules/auth/auth.routes.js';
import { logoutRoutes } from "./modules/auth/logout.routes.js";
import cookie from "@fastify/cookie";
import { authCallbackRoutes } from "./modules/auth/auth-callback.routes.js";
import { registerAuthCleanup } from "./modules/auth/auth-cleanup.js";


export async function buildApp() {
  const app = Fastify({ 
    bodyLimit: 1_048_576,
    logger: 
    { 
      redact: ['req.headers.authorization', 'req.headers.cookie', 'req.url'] 
    } 
  });
  
  app.decorateReply("authUser", null);
  

  await app.register(cors, 
    { 
      origin: config.frontendOrigin, 
      allowedHeaders: [
        "Content-Type",
        "Authorization",
        "Idempotency-Key",
      ],
    });

  await app.register(rateLimit) ;
  await app.register(cookie);
  await app.register(authCallbackRoutes);
  await app.register(authRoutes);
  await app.register(browserAuthRoutes);
  await app.register(logoutRoutes);
 
  
  


  app.get('/health', async () => ({ status: 'ok', service: 'bmms-api' }));
  app.get('/ready', async (_request, reply) => {
    try {
      await pool.query('SELECT 1');
      return { status: 'ready', database: 'connected' };
    } catch {
      return reply.code(503).send({ status: 'not_ready', database: 'unavailable' });
    }
  });
  
  app.addHook("onClose", async () => {
  await pool.end();
});

registerAuthCleanup(app);

  return app;
}


