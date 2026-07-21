import { FastifyReply, FastifyRequest } from 'fastify';
import crypto from 'crypto';
import argon2 from 'argon2';
import db from '../db/database';

// Cookie name. Deliberately NOT the "__Host-" prefix by default: browsers discard
// a __Host- cookie *silently* unless every requirement holds exactly (Secure +
// Path=/ + no Domain + secure origin). Behind a reverse proxy that produces a
// login which returns 200 and then 401s on the very next request, with nothing in
// any log to explain it. Opt back in via ARTIST_COOKIE_NAME=__Host-artist_session
// once you've confirmed the deployment is end-to-end HTTPS.
export const ARTIST_COOKIE_NAME = process.env.ARTIST_COOKIE_NAME ?? 'artist_session';
export const ARTIST_SESSION_TTL_SECONDS = Number(process.env.ARTIST_SESSION_TTL_SECONDS ?? 60 * 60 * 12);
export const ARTIST_PASSWORD_HASH = process.env.ARTIST_PASSWORD_HASH ?? '';
// Secure defaults on in production but can be forced off for a plain-HTTP host.
export const ARTIST_COOKIE_SECURE =
    (process.env.ARTIST_COOKIE_SECURE ?? (process.env.NODE_ENV === 'production' ? 'true' : 'false')) === 'true';
// 'lax' rather than 'strict': strict buys nothing here (every state-changing call
// is a same-origin fetch) and is a common cause of cookies going missing after an
// external navigation or redirect.
export const ARTIST_COOKIE_SAMESITE =
    (process.env.ARTIST_COOKIE_SAMESITE ?? 'lax') as 'strict' | 'lax' | 'none';

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
        // Log *why* at warn level so it surfaces in production. This distinguishes
        // the two failure modes that look identical from the browser: the cookie
        // never came back (browser refused to store it — check Secure/SameSite and
        // that the site is HTTPS end to end) versus the cookie arrived but its
        // session is gone (expired, or the DB was reset). Names only, no values.
        const names = Object.keys((req as any).cookies ?? {});
        req.log.warn(
            { cookiesReceived: names, expecting: ARTIST_COOKIE_NAME, hasSessionCookie: names.includes(ARTIST_COOKIE_NAME) },
            names.includes(ARTIST_COOKIE_NAME)
                ? 'Artist auth failed: session cookie present but not valid (expired or unknown session).'
                : 'Artist auth failed: no session cookie sent by the browser — it likely refused to store it.'
        );
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