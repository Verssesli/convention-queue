import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import crypto from 'crypto';
import QRCode from 'qrcode';
import db from '../db/database';

// ── Storage ──
// The access hash is the value encoded in the artist's QR code. Exactly one may
// exist at a time (enforced by the CHECK on the primary key) and it lives in
// SQLite rather than memory, so a reboot doesn't silently invalidate every QR
// code the artist has already printed and put on their table.
db.exec(`
    CREATE TABLE IF NOT EXISTS queue_access (
        id         INTEGER PRIMARY KEY CHECK (id = 1),
        hash       TEXT    NOT NULL,
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS app_secret (
        name  TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
`);

export const ACCESS_COOKIE_NAME = process.env.ACCESS_COOKIE_NAME ?? 'queue_access';
export const ACCESS_TTL_SECONDS = Number(process.env.ACCESS_TTL_SECONDS ?? 60 * 60 * 24 * 3);
export const ACCESS_COOKIE_SECURE =
    (process.env.ACCESS_COOKIE_SECURE ?? (process.env.NODE_ENV === 'production' ? 'true' : 'false')) === 'true';

const HASH_LENGTH = Number(process.env.ACCESS_HASH_LENGTH ?? 10);
// No vowels (avoids accidental words) and no 0/1/l/i (avoids misreads if anyone
// ever types it by hand). ~33^10 ≈ 1.5e15 combinations, far past guessing.
const ALPHABET = 'bcdfghjkmnpqrstvwxyz23456789';

function randomHash(): string {
    let out = '';
    for (let i = 0; i < HASH_LENGTH; i++) out += ALPHABET[crypto.randomInt(0, ALPHABET.length)];
    return out;
}

export function getAccessHash(): string {
    const row = db.prepare('SELECT hash FROM queue_access WHERE id = 1').get() as { hash: string } | undefined;
    return row ? row.hash : regenerateAccessHash();
}

export function regenerateAccessHash(): string {
    const hash = randomHash();
    db.prepare(`
        INSERT INTO queue_access (id, hash, created_at) VALUES (1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET hash = excluded.hash, created_at = excluded.created_at
    `).run(hash, Date.now());
    return hash;
}

// ── Attendee access token ──
// The cookie is an HMAC-signed grant rather than a copy of the hash. That way
// regenerating the QR code stops the old link working for *new* arrivals without
// kicking everyone already waiting in the queue out of their spot. The signing
// key is persisted so grants survive a reboot too.
function getSecret(): string {
    const row = db.prepare('SELECT value FROM app_secret WHERE name = ?').get('access_hmac') as { value: string } | undefined;
    if (row) return row.value;
    const value = crypto.randomBytes(32).toString('base64');
    db.prepare('INSERT INTO app_secret (name, value) VALUES (?, ?)').run('access_hmac', value);
    return value;
}

function sign(payload: string): string {
    return crypto.createHmac('sha256', getSecret()).update(payload).digest('base64url');
}

export function makeAccessToken(): string {
    const issuedAt = String(Date.now());
    return `${issuedAt}.${sign(issuedAt)}`;
}

export function hasQueueAccess(req: FastifyRequest): boolean {
    const token = (req as any).cookies?.[ACCESS_COOKIE_NAME] as string | undefined;
    if (!token) return false;

    const dot = token.lastIndexOf('.');
    if (dot <= 0) return false;

    const issuedAt = token.slice(0, dot);
    const provided = Buffer.from(token.slice(dot + 1));
    const expected = Buffer.from(sign(issuedAt));
    if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) return false;

    const issued = Number(issuedAt);
    return Number.isFinite(issued) && Date.now() - issued < ACCESS_TTL_SECONDS * 1000;
}

export function grantQueueAccess(reply: FastifyReply) {
    reply.setCookie(ACCESS_COOKIE_NAME, makeAccessToken(), {
        httpOnly: true,
        secure: ACCESS_COOKIE_SECURE,
        sameSite: 'lax',
        path: '/',
        maxAge: ACCESS_TTL_SECONDS,
    });
}

// Constant-time compare so the hash can't be recovered a character at a time.
export function matchesAccessHash(candidate: string): boolean {
    const a = Buffer.from(candidate);
    const b = Buffer.from(getAccessHash());
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ── Artist-facing QR routes (auth applied in server.ts) ──
function publicBaseUrl(req: FastifyRequest): string {
    const configured = process.env.PUBLIC_BASE_URL;
    if (configured) return configured.replace(/\/+$/, '');
    // trustProxy makes req.protocol honour X-Forwarded-Proto, so this resolves to
    // the real public https://host behind nginx without extra configuration.
    return `${req.protocol}://${req.headers.host}`;
}

async function describeAccess(req: FastifyRequest) {
    const hash = getAccessHash();
    const url = `${publicBaseUrl(req)}/${hash}`;
    const qrDataUrl = await QRCode.toDataURL(url, {
        width: 640,
        margin: 2,
        errorCorrectionLevel: 'M',
        color: { dark: '#000000ff', light: '#ffffffff' },
    });
    return { hash, url, qrDataUrl };
}

export async function artistAccessRoutes(app: FastifyInstance) {
    app.get('/api/artist/qr', async (req: FastifyRequest) => describeAccess(req));

    app.post('/api/artist/qr/regenerate', async (req: FastifyRequest) => {
        regenerateAccessHash();
        return describeAccess(req);
    });
}
