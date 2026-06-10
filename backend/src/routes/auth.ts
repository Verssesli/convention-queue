import { FastifyReply, FastifyRequest } from 'fastify';
import crypto from 'crypto';
import argon2 from 'argon2';
import db from '../db/database';

export const ARTIST_COOKIE_NAME = process.env.ARTIST_COOKIE_NAME ?? (
    process.env.NODE_ENV === 'production' ? '__Host-artist_session' : 'artist_session'
);
export const ARTIST_SESSION_TTL_SECONDS = Number(process.env.ARTIST_SESSION_TTL_SECONDS ?? 60 * 60 * 12);
export const ARTIST_PASSWORD_HASH = process.env.ARTIST_PASSWORD_HASH ?? '';
export const ARTIST_COOKIE_SECURE = process.env.NODE_ENV === 'production';
export const ARTIST_COOKIE_SAMESITE: 'strict' | 'lax' = 'strict';

// Per-IP login rate limit. Logins are rare (only the artist), so a tight limit is
// safe even behind shared NAT and it blunts password brute-forcing.
const LOGIN_RATE_MAX = Number(process.env.LOGIN_RATE_MAX ?? 10);
const LOGIN_RATE_WINDOW = process.env.LOGIN_RATE_WINDOW ?? '1 minute';

// argon2 here uses ~64 MB per verify. Without a ceiling, many concurrent /api/login
// requests could allocate gigabytes and OOM the box. Cap how many verifies may run
// at once; excess requests are rejected fast rather than piling up memory.
const MAX_CONCURRENT_VERIFIES = Number(process.env.MAX_CONCURRENT_VERIFIES ?? 4);
let activeVerifies = 0;

// ── Create sessions table if it doesn't exist ──
db.exec(`
    CREATE TABLE IF NOT EXISTS artist_session (
        session_id   TEXT PRIMARY KEY,
        created_at   INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL
    );
`);

function base64url(bytes: Buffer) {
    return bytes.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function newSessionId() {
    return base64url(crypto.randomBytes(32));
}

function isExpired(lastSeenAt: number) {
    return Date.now() - lastSeenAt > ARTIST_SESSION_TTL_SECONDS * 1000;
}

export function isArtistAuthed(req: FastifyRequest): boolean {
    const sid = (req as any).cookies?.[ARTIST_COOKIE_NAME];
    if (!sid) return false;

    const row = db.prepare(
        'SELECT last_seen_at FROM artist_session WHERE session_id = ?'
    ).get(sid) as { last_seen_at: number } | undefined;

    if (!row) return false;

    if (isExpired(row.last_seen_at)) {
        db.prepare('DELETE FROM artist_session WHERE session_id = ?').run(sid);
        return false;
    }

    db.prepare('UPDATE artist_session SET last_seen_at = ? WHERE session_id = ?')
        .run(Date.now(), sid);

    return true;
}

export async function requireArtistAuth(req: FastifyRequest, reply: FastifyReply) {
    if (!isArtistAuthed(req)) {
        return reply.code(401).send({ message: 'Unauthorized' });
    }
}

export function registerArtistAuthRoutes(app: any) {
    app.post('/api/login', {
        config: { rateLimit: { max: LOGIN_RATE_MAX, timeWindow: LOGIN_RATE_WINDOW } },
    }, async (req: FastifyRequest, reply: FastifyReply) => {
        const body = req.body as { password?: string } | undefined;
        const password = String(body?.password ?? '');

        if (!ARTIST_PASSWORD_HASH) {
            return reply.code(500).send({ message: 'Auth not configured.' });
        }

        if (activeVerifies >= MAX_CONCURRENT_VERIFIES) {
            return reply.code(503).send({ message: 'Server busy, please try again.' });
        }

        let ok: boolean;
        activeVerifies++;
        try {
            ok = await argon2.verify(ARTIST_PASSWORD_HASH, password);
        } finally {
            activeVerifies--;
        }
        if (!ok) {
            return reply.code(401).send({ message: 'Incorrect password.' });
        }

        const sid = newSessionId();
        const now = Date.now();

        db.prepare(
            'INSERT INTO artist_session (session_id, created_at, last_seen_at) VALUES (?, ?, ?)'
        ).run(sid, now, now);

        reply.setCookie(ARTIST_COOKIE_NAME, sid, {
            httpOnly: true,
            secure: ARTIST_COOKIE_SECURE,
            sameSite: ARTIST_COOKIE_SAMESITE,
            path: '/',
            maxAge: ARTIST_SESSION_TTL_SECONDS,
        });

        return { ok: true };
    });

    app.post('/api/logout', async (req: FastifyRequest, reply: FastifyReply) => {
        const sid = (req as any).cookies?.[ARTIST_COOKIE_NAME];
        if (sid) {
            db.prepare('DELETE FROM artist_session WHERE session_id = ?').run(sid);
        }

        reply.clearCookie(ARTIST_COOKIE_NAME, {
            path: '/',
            secure: ARTIST_COOKIE_SECURE,
            sameSite: ARTIST_COOKIE_SAMESITE,
        });

        return { ok: true };
    });

    app.get('/api/me', async (req: FastifyRequest, reply: FastifyReply) => {
        if (!isArtistAuthed(req)) return reply.code(401).send({ authenticated: false });
        return { authenticated: true };
    });
}