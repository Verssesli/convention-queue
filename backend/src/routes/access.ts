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
export const ACCESS_COOKIE_SECURE =
    (process.env.ACCESS_COOKIE_SECURE ?? (process.env.NODE_ENV === 'production' ? 'true' : 'false')) === 'true';

// ── Access lifetime ──
// A scan is good until the end of the event day, not for a rolling window, so
// yesterday's attendees can't queue up before today's doors open.
//
// The zone must be the *event's*, not the server's: on a VPS in another region
// "end of day" would otherwise land in the middle of the convention. Defaults to
// the host's zone, which is right when the server sits at the venue.
function resolveTimeZone(): string {
    const configured = process.env.EVENT_TIMEZONE;
    const hostZone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
    if (!configured) return hostZone;
    try {
        new Intl.DateTimeFormat('en-US', { timeZone: configured });
        return configured;
    } catch {
        console.warn(`EVENT_TIMEZONE "${configured}" is not a valid IANA zone; falling back to ${hostZone}.`);
        return hostZone;
    }
}
export const EVENT_TIMEZONE = resolveTimeZone();

// Hour (0–23) at which one event day rolls into the next. 0 = midnight. Raise it
// for late-running events so a queue still live at 23:59 isn't cut off mid-line;
// 4 means "4am counts as the previous day", which still blocks next-day arrivals.
const DAY_ROLLOVER_HOUR = Math.min(23, Math.max(0, Number(process.env.ACCESS_DAY_ROLLOVER_HOUR ?? 0)));

// Wall-clock fields for an instant, in the event's zone.
function wallClockParts(instant: Date) {
    const parts = new Intl.DateTimeFormat('en-US', {
        timeZone: EVENT_TIMEZONE, hour12: false,
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
    }).formatToParts(instant);

    const get = (type: string) => Number(parts.find(p => p.type === type)!.value);
    // Some ICU builds render midnight as hour 24 under hour12:false.
    const hour = get('hour') % 24;
    return { year: get('year'), month: get('month'), day: get('day'), hour, minute: get('minute'), second: get('second') };
}

// Offset between the event zone and UTC at a given instant, in ms.
function zoneOffsetMs(instant: Date): number {
    const w = wallClockParts(instant);
    const asIfUtc = Date.UTC(w.year, w.month - 1, w.day, w.hour, w.minute, w.second);
    return asIfUtc - (instant.getTime() - instant.getMilliseconds());
}

/** Epoch ms of the next day-rollover boundary in the event's timezone. */
export function endOfEventDay(now: Date = new Date()): number {
    const offset = zoneOffsetMs(now);
    const w = wallClockParts(now);

    // Today's boundary if we haven't reached it yet, otherwise tomorrow's.
    const boundaryIsToday = w.hour < DAY_ROLLOVER_HOUR;
    const wallBoundary = Date.UTC(w.year, w.month - 1, w.day + (boundaryIsToday ? 0 : 1), DAY_ROLLOVER_HOUR, 0, 0, 0);

    // Re-resolve the offset at the boundary itself so a DST shift between now and
    // then doesn't move the cutoff by an hour.
    let instant = wallBoundary - offset;
    const offsetThen = zoneOffsetMs(new Date(instant));
    if (offsetThen !== offset) instant = wallBoundary - offsetThen;
    return instant;
}

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

// The token carries its own absolute expiry, so the deadline is fixed at scan
// time and can't be extended by simply coming back later in the day.
export function makeAccessToken(expiresAt: number): string {
    const payload = String(expiresAt);
    return `${payload}.${sign(payload)}`;
}

export function hasQueueAccess(req: FastifyRequest): boolean {
    const token = (req as any).cookies?.[ACCESS_COOKIE_NAME] as string | undefined;
    if (!token) return false;

    const dot = token.lastIndexOf('.');
    if (dot <= 0) return false;

    const payload = token.slice(0, dot);
    const provided = Buffer.from(token.slice(dot + 1));
    const expected = Buffer.from(sign(payload));
    if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) return false;

    const expiresAt = Number(payload);
    return Number.isFinite(expiresAt) && Date.now() < expiresAt;
}

export function grantQueueAccess(reply: FastifyReply) {
    const expiresAt = endOfEventDay();
    // Cookie lifetime mirrors the signed expiry so the browser drops it on its own
    // too. Floor of 1s keeps setCookie valid for a scan in the final second.
    const maxAge = Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000));
    reply.setCookie(ACCESS_COOKIE_NAME, makeAccessToken(expiresAt), {
        httpOnly: true,
        secure: ACCESS_COOKIE_SECURE,
        sameSite: 'lax',
        path: '/',
        maxAge,
    });
}

// Constant-time compare so the hash can't be recovered a character at a time.
export function matchesAccessHash(candidate: string): boolean {
    const a = Buffer.from(candidate);
    const b = Buffer.from(getAccessHash());
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ── Artist-facing QR routes (auth applied in server.ts) ──
// An origin that would produce a QR code nobody outside this machine can scan.
function isUnreachableHost(host: string): boolean {
    const bare = host.replace(/:\d+$/, '').replace(/^\[|]$/g, '').toLowerCase();
    return bare === 'localhost'
        || bare === '::1'
        || bare === '0.0.0.0'
        || /^127\./.test(bare)
        || /^10\./.test(bare)
        || /^192\.168\./.test(bare)
        || /^172\.(1[6-9]|2\d|3[01])\./.test(bare);
}

// Accepts only a bare scheme://host[:port] origin, so a bad value can't smuggle a
// path or querystring into the QR target.
function sanitiseOrigin(value?: string): string | null {
    if (!value) return null;
    try {
        const u = new URL(value);
        if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
        if (!u.hostname) return null;
        return u.origin;
    } catch {
        return null;
    }
}

/**
 * Resolve the public origin attendees will actually reach, in order of trust:
 *   1. PUBLIC_BASE_URL — explicit config always wins.
 *   2. X-Forwarded-Host / Host — correct when the proxy forwards the real host.
 *      nginx does NOT do this by default: it sends the upstream address, so this
 *      yields 127.0.0.1:<port> unless `proxy_set_header Host $host;` is set.
 *   3. The origin reported by the artist's own browser. They are authenticated
 *      and are looking at the very domain attendees will use, so this is a
 *      reliable last resort that keeps the QR correct on a default nginx setup.
 */
function publicBaseUrl(req: FastifyRequest, clientOrigin?: string): string {
    const configured = sanitiseOrigin(process.env.PUBLIC_BASE_URL);
    if (configured) return configured;

    // trustProxy makes both of these honour X-Forwarded-Proto / X-Forwarded-Host.
    const headerHost = (req as any).host || req.headers.host;
    if (headerHost && !isUnreachableHost(headerHost)) {
        return `${req.protocol}://${headerHost}`;
    }

    const fromBrowser = sanitiseOrigin(clientOrigin);
    if (fromBrowser && !isUnreachableHost(new URL(fromBrowser).host)) {
        req.log.warn(
            { headerHost, using: fromBrowser },
            'QR link: proxy did not forward the public host (add `proxy_set_header Host $host;` to nginx, ' +
            'or set PUBLIC_BASE_URL). Falling back to the origin reported by the artist\'s browser.'
        );
        return fromBrowser;
    }

    // Nothing usable — emit the best guess but make the misconfiguration loud.
    const fallback = `${req.protocol}://${headerHost ?? 'localhost'}`;
    req.log.warn(
        { headerHost, clientOrigin, using: fallback },
        'QR link points at a non-public address and will not be scannable. ' +
        'Set PUBLIC_BASE_URL, or add `proxy_set_header Host $host;` to your nginx location block.'
    );
    return fallback;
}

async function describeAccess(req: FastifyRequest, clientOrigin?: string) {
    const hash = getAccessHash();
    const base = publicBaseUrl(req, clientOrigin);
    const url = `${base}/${hash}`;
    const qrDataUrl = await QRCode.toDataURL(url, {
        width: 640,
        margin: 2,
        errorCorrectionLevel: 'M',
        color: { dark: '#000000ff', light: '#ffffffff' },
    });
    return { hash, url, qrDataUrl, reachable: !isUnreachableHost(new URL(base).host) };
}

type OriginQuery = { Querystring: { origin?: string } };

export async function artistAccessRoutes(app: FastifyInstance) {
    app.get('/api/artist/qr', async (req: FastifyRequest<OriginQuery>) =>
        describeAccess(req, req.query.origin));

    app.post('/api/artist/qr/regenerate', async (req: FastifyRequest<OriginQuery>) => {
        regenerateAccessHash();
        return describeAccess(req, req.query.origin);
    });
}
