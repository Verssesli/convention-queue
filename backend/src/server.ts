import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import multipart from '@fastify/multipart';
import staticFiles from '@fastify/static';
import rateLimit from '@fastify/rate-limit';
import path from 'path';

import fs from 'fs';

import { queueRoutes, artistQueueRoutes, startQueuePruning } from './routes/queue';
import { catalogueReadRoutes, catalogueWriteRoutes } from './routes/catalogue';
import { registerArtistAuthRoutes, requireArtistAuth } from './routes/auth';
import { artistAccessRoutes, grantQueueAccess, hasQueueAccess, matchesAccessHash } from './routes/access';

// Schema is created in db/database.ts — see the note there on import ordering.

const HOST = process.env.HOST ?? '0.0.0.0';
const PORT = Number(process.env.PORT ?? 3000);
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR ?? path.join(__dirname, '../uploads'));
const FRONTEND_DIR = path.resolve(process.env.FRONTEND_DIR ?? path.join(__dirname, '../../frontend'));
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB ?? 20);

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

    // Keep this in step with the reverse proxy's body limit. nginx defaults to
    // client_max_body_size 1m and rejects anything larger with its own HTML page,
    // before the request ever reaches here — so a mismatch shows up as an upload
    // failure the app never sees and cannot explain.
    await app.register(multipart, {
        limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024 },
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

    // ── Attendee access gate ──
    // The queue is only joinable by scanning the QR code at the artist's table.
    // Anyone arriving at the bare domain, or on a stale/guessed hash, gets the
    // "invalid link" page instead of the app. Registered after @fastify/cookie so
    // req.cookies is already parsed by the time this runs.
    const readFrontend = (name: string) => fs.readFileSync(path.join(FRONTEND_DIR, name), 'utf8');
    const ALWAYS_ALLOWED = new Set(['/artist', '/artist.html', '/invalid.html', '/favicon.ico', '/robots.txt']);
    const ALLOWED_PREFIXES = ['/api/', '/uploads/'];
    // A single path segment of hash-shaped characters, e.g. /djioa
    const HASH_PATH = /^\/([A-Za-z0-9_-]{4,64})\/?$/;

    const sendApp = (reply: any) => reply.code(200).type('text/html; charset=utf-8').send(readFrontend('index.html'));
    const sendInvalid = (reply: any) => reply.code(403).type('text/html; charset=utf-8').send(readFrontend('invalid.html'));

    app.addHook('onRequest', async (req, reply) => {
        const url = (req.raw.url ?? '/').split('?')[0];

        if (ALWAYS_ALLOWED.has(url)) return;
        if (ALLOWED_PREFIXES.some(p => url.startsWith(p))) return;

        const isRoot = url === '/' || url === '/index.html';
        const hashMatch = url.match(HASH_PATH);

        if (hashMatch) {
            // Arriving via a QR link. A valid hash mints the access cookie and the
            // app is served straight from this URL — no redirect, so there's no
            // history entry pointing at the secret for anyone to go "back" to.
            // The page itself then scrubs the hash out of the address bar.
            if (matchesAccessHash(hashMatch[1])) {
                grantQueueAccess(reply);
                return sendApp(reply);
            }
            return sendInvalid(reply);
        }

        if (isRoot) {
            return hasQueueAccess(req) ? undefined : sendInvalid(reply);
        }

        // Anything else falls through to the static handler (and its 404).
        return;
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

    await app.register(async (instance) => {
        instance.addHook('preHandler', requireArtistAuth);
        await artistAccessRoutes(instance);
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