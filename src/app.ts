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
import { organizationRoutes } from "./modules/organizations/organization.routes.js";
import { provisioningRoutes } from './modules/provisioning/provisioning.routes.js';
import { invitationRoutes } from './modules/invitations/invitation.routes.js';
export async function buildApp() {
  const app = Fastify({ 
    bodyLimit: 1_048_576,
    // Behind a reverse proxy (LAN setup), trust only that proxy's address
    // for X-Forwarded-For, so rate limits apply per client.
    trustProxy: config.trustProxy,
    logger: 
    { 
      redact: ['req.headers.authorization', 'req.headers.cookie', 'req.url'] 
    } ,
    ajv: {
  customOptions: {
    removeAdditional: false,
  },
},
  });
  
  app.decorateReply("authUser", null);
  

  await app.register(cors, 
    { 
      origin: config.frontendOrigin, 
      // Lets the frontend send the bmms_session cookie.
      credentials: true,
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
  await app.register(provisioningRoutes);
  await app.register(organizationRoutes);
  await app.register(invitationRoutes);


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


