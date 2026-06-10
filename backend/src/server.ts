import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import multipart from '@fastify/multipart';
import staticFiles from '@fastify/static';
import rateLimit from '@fastify/rate-limit';
import path from 'path';

import db from './db/database';
import { queueRoutes, artistQueueRoutes, startQueuePruning } from './routes/queue';
import { catalogueReadRoutes, catalogueWriteRoutes } from './routes/catalogue';
import { registerArtistAuthRoutes, requireArtistAuth } from './routes/auth';

// ── Run migration on startup ──
db.exec(`
CREATE TABLE IF NOT EXISTS queue_entry (
queue_id TEXT PRIMARY KEY,
queue_number INTEGER NOT NULL,
joined_at TEXT NOT NULL,
allowed_in_at TEXT,
expires_at TEXT,
left_queue INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS catalogue_image (
image_key TEXT PRIMARY KEY,
image_url TEXT NOT NULL,
image_order INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_queue_number ON queue_entry(queue_number);
CREATE INDEX IF NOT EXISTS idx_queue_waiting ON queue_entry(allowed_in_at, left_queue, queue_number);
`);



const HOST = process.env.HOST ?? '0.0.0.0';
const PORT = Number(process.env.PORT ?? 3000);
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR ?? path.join(__dirname, '../uploads'));
const FRONTEND_DIR = path.resolve(process.env.FRONTEND_DIR ?? path.join(__dirname, '../../frontend'));

const app = Fastify({
    // The app runs behind a reverse proxy (binds 127.0.0.1), so the real client
    // IP arrives via X-Forwarded-For. Without this, req.ip is always the proxy's
    // loopback address and every user would share one rate-limit bucket. Default
    // 'loopback' trusts only the local proxy and is also safe when run directly.
    trustProxy: process.env.TRUST_PROXY ?? 'loopback',
    logger: process.env.NODE_ENV === 'production'
        ? { level: 'warn' }
        : true,
});

async function start() {
    await app.register(cors, {
        origin: process.env.CORS_ORIGIN ?? true,
        credentials: true,
    });

    await app.register(cookie);

    // Rate limiting — registered with global:false so it never throttles the
    // high-volume status-poll endpoint. At a convention hundreds of attendees
    // sit behind a single NAT/WiFi public IP, so a blanket per-IP limit would
    // punish legitimate users. Limits are opted-in per route (join/requeue/login)
    // and kept lenient enough to survive a NAT crowd but lethal to a single
    // scripted IP. See routes/queue.ts and routes/auth.ts for the hard caps.
    await app.register(rateLimit, {
        global: false,
        // shared store across all routes; per-route config overrides max/timeWindow
        max: 100,
        timeWindow: '1 minute',
    });

    await app.register(multipart, {
        limits: { fileSize: 20 * 1024 * 1024 },
    });

    await app.register(staticFiles, {
        root: UPLOAD_DIR,
        prefix: '/uploads/',
        decorateReply: false,
    });

    await app.register(staticFiles, {
        root: FRONTEND_DIR,
        prefix: '/',
        decorateReply: true,
        index: 'index.html',
    });

    registerArtistAuthRoutes(app);

    await app.register(queueRoutes);
    await app.register(catalogueReadRoutes);

    await app.register(async (instance) => {
        instance.addHook('preHandler', requireArtistAuth);
        await artistQueueRoutes(instance);
    });

    await app.register(async (instance) => {
        instance.addHook('preHandler', requireArtistAuth);
        await catalogueWriteRoutes(instance);
    });

    app.get('/artist', async (_req, reply) => {
        return reply.sendFile('artist.html');
    });

    try {
        await app.listen({ port: PORT, host: HOST });
        startQueuePruning(app.log);
        console.log(`Server running at http://${HOST}:${PORT}`);
    } catch (err) {
        app.log.error(err);
        process.exit(1);
    }
}

start().catch((err) => {
    console.error(err);
    process.exit(1);
});