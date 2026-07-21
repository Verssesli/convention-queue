import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { v4 as uuidv4 } from 'uuid';
import db from '../db/database';
import { hasQueueAccess } from './access';

const NO_ACCESS_MESSAGE = 'Please scan the QR code at the artist\'s table to join the queue.';
// Machine-readable so the client can tell "your scan is no longer valid" apart
// from any other 403 and hand the user over to the server's error page.
const NO_ACCESS_CODE = 'NO_QUEUE_ACCESS';

let ACCESS_WINDOW_MINUTES = Number(process.env.ACCESS_WINDOW_MINUTES ?? 30);

// ── Abuse / growth bounds ──
// Hard cap on people *still waiting* (left_queue = 0, not yet allowed). This is
// the real DoS bound: it's global rather than per-IP, so it can't be defeated
// by spreading a flood across IPs and — crucially — it doesn't punish the many
// legitimate attendees who share one convention-WiFi NAT address.
const MAX_WAITING_ENTRIES = Number(process.env.MAX_WAITING_ENTRIES ?? 2000);

// Per-IP rate limits for the join/requeue write endpoints. Lenient enough that a
// crowd arriving on the same NAT IP isn't blocked, but it stops a single browser
// or script from hammering the endpoint. Tune via env if your NAT is very dense.
const JOIN_RATE_MAX = Number(process.env.JOIN_RATE_MAX ?? 30);
const JOIN_RATE_WINDOW = process.env.JOIN_RATE_WINDOW ?? '1 minute';

// Pruning — completed/abandoned rows are deleted after this many hours so the
// table (and the artist payload) can't grow without bound over a multi-day event.
const PRUNE_RETENTION_HOURS = Number(process.env.PRUNE_RETENTION_HOURS ?? 24);
const PRUNE_INTERVAL_MINUTES = Number(process.env.PRUNE_INTERVAL_MINUTES ?? 30);

class QueueFullError extends Error {
    constructor() {
        super('The queue is currently full. Please try again shortly.');
        this.name = 'QueueFullError';
    }
}

// Cached in memory — only changes when the artist allows users in.
// Initialised from DB on startup so a server restart doesn't reset it.
let cachedHighestServing: number | null = (() => {
    const row = db.prepare(`
        SELECT MAX(queue_number) AS max_num
        FROM queue_entry
        WHERE allowed_in_at IS NOT NULL AND left_queue = 0
    `).get() as { max_num: number | null };
    return row?.max_num ?? null;
})();

interface QueueEntry {
    queue_id: string;
    queue_number: number;
    joined_at: string;
    allowed_in_at: string | null;
    expires_at: string | null;
    left_queue: number;
}

function formatEntry(e: QueueEntry) {
    return {
        queueId:                   e.queue_id,
        queueNumber:               e.queue_number,
        joinedAt:                  e.joined_at,
        allowedIn:                 e.allowed_in_at ?? null,
        expiresAt:                 e.expires_at ?? null,
        leftQueue:                 Boolean(e.left_queue),
        currentTime:               new Date().toISOString(),
        highestServingQueueNumber: cachedHighestServing,
    };
}

// Transaction-wrapped insert — prevents race conditions on concurrent joins, and
// enforces MAX_WAITING_ENTRIES atomically so a flood can't slip past the check.
const assignNumber = db.transaction((queueId: string, joinedAt: string) => {
    const waitingRow = db.prepare(
        `SELECT COUNT(*) AS waiting FROM queue_entry WHERE left_queue = 0 AND allowed_in_at IS NULL`
    ).get() as { waiting: number };
    if (waitingRow.waiting >= MAX_WAITING_ENTRIES) {
        throw new QueueFullError();
    }
    const maxRow = db.prepare(
        `SELECT MAX(queue_number) AS max_num FROM queue_entry`
    ).get() as { max_num: number | null };
    const queueNumber = (maxRow?.max_num ?? 0) + 1;
    db.prepare(`
        INSERT INTO queue_entry (queue_id, queue_number, joined_at, allowed_in_at, expires_at, left_queue)
        VALUES (?, ?, ?, NULL, NULL, 0)
    `).run(queueId, queueNumber, joinedAt);
    return queueNumber;
});

// Delete completed/abandoned entries older than the retention window. Entries that
// are still waiting or inside a live access window are always kept. Returns the
// number of rows removed.
export function pruneQueue(): number {
    const cutoff = new Date(Date.now() - PRUNE_RETENTION_HOURS * 3_600_000).toISOString();
    const result = db.prepare(`
        DELETE FROM queue_entry
        WHERE joined_at < ?
          AND (
                left_queue = 1
                OR (expires_at IS NOT NULL AND expires_at < ?)
              )
    `).run(cutoff, new Date().toISOString());
    return result.changes;
}

// Periodic pruning loop, started once after the server begins listening.
export function startQueuePruning(log?: { info: (msg: string) => void; error: (err: unknown) => void }) {
    const tick = () => {
        try {
            const removed = pruneQueue();
            if (removed > 0) log?.info(`Pruned ${removed} stale queue entr${removed === 1 ? 'y' : 'ies'}.`);
        } catch (err) {
            log?.error(err);
        }
    };
    tick(); // run once on startup
    const handle = setInterval(tick, PRUNE_INTERVAL_MINUTES * 60_000);
    handle.unref?.(); // don't keep the process alive solely for pruning
    return handle;
}

export async function queueRoutes(app: FastifyInstance) {

    // POST /api/queue/join — create a new queue entry
    app.post('/api/queue/join', {
        config: { rateLimit: { max: JOIN_RATE_MAX, timeWindow: JOIN_RATE_WINDOW } },
    }, async (req: FastifyRequest, reply: FastifyReply) => {
        // Gating the page alone would be cosmetic — the endpoint is what actually
        // creates entries, so it has to check too.
        if (!hasQueueAccess(req)) return reply.status(403).send({ code: NO_ACCESS_CODE, message: NO_ACCESS_MESSAGE });

        const queueId = uuidv4();
        const joinedAt = new Date().toISOString();
        try {
            assignNumber(queueId, joinedAt);
        } catch (err) {
            if (err instanceof QueueFullError) return reply.status(503).send({ message: err.message });
            throw err;
        }
        const entry = db.prepare(`SELECT * FROM queue_entry WHERE queue_id = ?`).get(queueId) as QueueEntry;
        return formatEntry(entry);
    });

    // GET /api/queue/status?queueId=... — refresh one user's status
    app.get('/api/queue/status', async (req: FastifyRequest<{ Querystring: { queueId: string } }>, reply: FastifyReply) => {
        const { queueId } = req.query;
        if (!queueId) return reply.status(400).send({ message: 'queueId is required' });

        const entry = db.prepare(`SELECT * FROM queue_entry WHERE queue_id = ?`).get(queueId) as QueueEntry | undefined;
        if (!entry) return reply.status(404).send({ message: 'Queue entry not found' });

        return formatEntry(entry);
    });

    // POST /api/queue/leave — mark a user as having left
    app.post('/api/queue/leave', async (req: FastifyRequest<{ Body: { queueId: string } }>, reply: FastifyReply) => {
        const { queueId } = req.body;
        if (!queueId) return reply.status(400).send({ message: 'queueId is required' });

        const result = db.prepare(`UPDATE queue_entry SET left_queue = 1 WHERE queue_id = ?`).run(queueId);
        if (result.changes === 0) return reply.status(404).send({ message: 'Queue entry not found' });

        return { ok: true, currentTime: new Date().toISOString() };
    });

    // POST /api/queue/requeue — leave old entry and create a new one
    app.post('/api/queue/requeue', {
        config: { rateLimit: { max: JOIN_RATE_MAX, timeWindow: JOIN_RATE_WINDOW } },
    }, async (req: FastifyRequest<{ Body: { queueId: string } }>, reply: FastifyReply) => {
        if (!hasQueueAccess(req)) return reply.status(403).send({ code: NO_ACCESS_CODE, message: NO_ACCESS_MESSAGE });

        const { queueId } = req.body;
        if (!queueId) return reply.status(400).send({ message: 'queueId is required' });

        const newId = uuidv4();
        const joinedAt = new Date().toISOString();

        try {
            db.transaction(() => {
                db.prepare(`UPDATE queue_entry SET left_queue = 1 WHERE queue_id = ?`).run(queueId);
                assignNumber(newId, joinedAt);
            })();
        } catch (err) {
            if (err instanceof QueueFullError) return reply.status(503).send({ message: err.message });
            throw err;
        }

        const entry = db.prepare(`SELECT * FROM queue_entry WHERE queue_id = ?`).get(newId) as QueueEntry;
        return { oldQueueId: queueId, ...formatEntry(entry) };
    });
}

// ── Artist-side queue routes (auth applied in server.ts) ──
export async function artistQueueRoutes(app: FastifyInstance) {

    // GET /api/artist/queue — full queue list
    app.get('/api/artist/queue', async (_req: FastifyRequest, _reply: FastifyReply) => {
        const entries = db.prepare(`SELECT * FROM queue_entry ORDER BY queue_number ASC`).all() as QueueEntry[];
        return {
            currentTime:               new Date().toISOString(),
            highestServingQueueNumber: cachedHighestServing,
            accessWindowMinutes:       ACCESS_WINDOW_MINUTES,
            entries: entries.map(e => ({
                queueId:     e.queue_id,
                queueNumber: e.queue_number,
                joinedAt:    e.joined_at,
                allowedIn:   e.allowed_in_at ?? null,
                expiresAt:   e.expires_at ?? null,
                leftQueue:   Boolean(e.left_queue),
            })),
        };
    });

    app.post('/api/artist/access-window', async (req: FastifyRequest<{ Body: { accessWindowMinutes: number } }>, reply: FastifyReply) => {
        const { accessWindowMinutes } = req.body;
        if (!accessWindowMinutes || accessWindowMinutes < 1)
            return reply.status(400).send({ message: 'access window must be >= 1' });
        ACCESS_WINDOW_MINUTES = accessWindowMinutes;
        return { ok: true };
    });

    // POST /api/artist/allow — allow the next X waiting users
    app.post('/api/artist/allow', async (req: FastifyRequest<{ Body: { count: number } }>, reply: FastifyReply) => {
        const { count } = req.body;
        if (!count || count < 1) return reply.status(400).send({ message: 'count must be >= 1' });

        const now = new Date();
        const expiresAt = new Date(now.getTime() + ACCESS_WINDOW_MINUTES * 60_000).toISOString();
        const allowedAt = now.toISOString();

        const waiting = db.prepare(`
            SELECT queue_id, queue_number FROM queue_entry
            WHERE allowed_in_at IS NULL AND left_queue = 0
            ORDER BY queue_number ASC
            LIMIT ?
        `).all(count) as { queue_id: string; queue_number: number }[];

        if (waiting.length === 0) {
            return { ok: true, currentTime: now.toISOString(), highestServingQueueNumber: cachedHighestServing, allowed: [] };
        }

        const update = db.prepare(`
            UPDATE queue_entry SET allowed_in_at = ?, expires_at = ? WHERE queue_id = ?
        `);

        db.transaction((rows: { queue_id: string; queue_number: number }[]) => {
            for (const row of rows) update.run(allowedAt, expiresAt, row.queue_id);
        })(waiting);

        // Update cache — highest number among the newly allowed batch
        const batchMax = Math.max(...waiting.map(w => w.queue_number));
        if (cachedHighestServing === null || batchMax > cachedHighestServing) {
            cachedHighestServing = batchMax;
        }

        return {
            ok:                        true,
            currentTime:               now.toISOString(),
            highestServingQueueNumber: cachedHighestServing,
            allowed: waiting.map(w => ({
                queueId:     w.queue_id,
                queueNumber: w.queue_number,
                allowedIn:   allowedAt,
                expiresAt:   expiresAt,
            })),
        };
    });

    // POST /api/artist/clear — clear all entries from the queue
    app.post('/api/artist/clear', async (_req: FastifyRequest, reply: FastifyReply) => {
        try {
            db.prepare('DELETE FROM queue_entry').run();
            cachedHighestServing = null;
            return { ok: true, currentTime: new Date().toISOString() };
        } catch (error) {
            return reply.status(500).send({ message: 'Failed to clear the queue database.' });
        }
    });
}