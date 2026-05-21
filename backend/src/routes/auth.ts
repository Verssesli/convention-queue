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
    app.post('/api/login', async (req: FastifyRequest, reply: FastifyReply) => {
        const body = req.body as { password?: string } | undefined;
        const password = String(body?.password ?? '');

        if (!ARTIST_PASSWORD_HASH) {
            return reply.code(500).send({ message: 'Auth not configured.' });
        }

        const ok = await argon2.verify(ARTIST_PASSWORD_HASH, password);
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