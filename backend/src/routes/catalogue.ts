import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';
import fs from 'fs';
import db from '../db/database';

const UPLOAD_DIR = process.env.UPLOAD_DIR ?? path.join(__dirname, '../../uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const UPLOAD_BASE_URL = process.env.UPLOAD_BASE_URL ?? '/uploads';

const UPLOAD_RATE_MAX = Number(process.env.UPLOAD_RATE_MAX ?? 20);
const UPLOAD_RATE_WINDOW = process.env.UPLOAD_RATE_WINDOW ?? '1 minute';

interface CatalogueImage {
    image_key: string;
    image_url: string;
    image_order: number;
}

async function saveFile(data: Buffer, originalName: string): Promise<{ imageKey: string; imageUrl: string }> {
    const ext = path.extname(originalName).toLowerCase() || '.jpg';
    const imageKey = uuidv4() + ext;
    const destPath = path.join(UPLOAD_DIR, imageKey);
    await fs.promises.writeFile(destPath, data);
    return { imageKey, imageUrl: `${UPLOAD_BASE_URL}/${imageKey}` };
}

// Public catalogue read — no password needed
export async function catalogueReadRoutes(app: FastifyInstance) {
    app.get('/api/catalogue', async (_req: FastifyRequest, _reply: FastifyReply) => {
        const rows = db.prepare(`SELECT * FROM catalogue_image ORDER BY image_order ASC`).all() as CatalogueImage[];
        return {
            images: rows.map(r => ({
                imageKey:  r.image_key,
                imageUrl:  r.image_url,
                order:     r.image_order,
            })),
        };
    });
}

// Artist catalogue management — password-protected
export async function catalogueWriteRoutes(app: FastifyInstance) {

    // POST /api/catalogue/upload
    // The only endpoints that accept a large body, so they're the only ones worth
    // flooding. The limit is per-IP and far above real use — an artist adds a
    // handful of images at a time — but caps how fast a stolen session, or anyone
    // probing the endpoint, can make the server take delivery of big payloads.
    app.post('/api/catalogue/upload', {
        config: { rateLimit: { max: UPLOAD_RATE_MAX, timeWindow: UPLOAD_RATE_WINDOW } },
    }, async (req: FastifyRequest, reply: FastifyReply) => {
        const data = await req.file();
        if (!data) return reply.status(400).send({ message: 'No file provided' });

        const buffer = await data.toBuffer();
        const { imageKey, imageUrl } = await saveFile(buffer, data.filename);

        const maxRow = db.prepare(`SELECT MAX(image_order) AS max_order FROM catalogue_image`).get() as { max_order: number | null };
        const order = (maxRow?.max_order ?? 0) + 1;

        db.prepare(`INSERT INTO catalogue_image (image_key, image_url, image_order) VALUES (?, ?, ?)`).run(imageKey, imageUrl, order);

        return { imageKey, imageUrl, order };
    });

    // PUT /api/catalogue/replace
    app.put('/api/catalogue/replace', {
        config: { rateLimit: { max: UPLOAD_RATE_MAX, timeWindow: UPLOAD_RATE_WINDOW } },
    }, async (req: FastifyRequest, reply: FastifyReply) => {
        const parts = req.parts();
        let imageKey = '';
        let fileBuffer: Buffer | null = null;
        let fileName = 'upload';

        for await (const part of parts) {
            if (part.type === 'field' && part.fieldname === 'imageKey') {
                imageKey = part.value as string;
            } else if (part.type === 'file' && part.fieldname === 'file') {
                fileBuffer = await part.toBuffer();
                fileName = part.filename;
            }
        }

        if (!imageKey || !fileBuffer) return reply.status(400).send({ message: 'imageKey and file are required' });

        const existing = db.prepare(`SELECT * FROM catalogue_image WHERE image_key = ?`).get(imageKey) as CatalogueImage | undefined;
        if (!existing) return reply.status(404).send({ message: 'Image not found' });

        // Delete old file
        const oldPath = path.join(UPLOAD_DIR, path.basename(existing.image_url));
        fs.unlink(oldPath, () => {});

        const ext = path.extname(fileName).toLowerCase() || '.jpg';
        const newKey = uuidv4() + ext;
        const newUrl = `${UPLOAD_BASE_URL}/${newKey}`;
        await fs.promises.writeFile(path.join(UPLOAD_DIR, newKey), fileBuffer);

        db.prepare(`UPDATE catalogue_image SET image_key = ?, image_url = ? WHERE image_key = ?`).run(newKey, newUrl, imageKey);

        return { imageKey: newKey, imageUrl: newUrl, order: existing.image_order };
    });

    // DELETE /api/catalogue/remove
    app.delete('/api/catalogue/remove', async (req: FastifyRequest<{ Body: { imageKey: string } }>, reply: FastifyReply) => {
        const { imageKey } = req.body;
        if (!imageKey) return reply.status(400).send({ message: 'imageKey is required' });

        const existing = db.prepare(`SELECT * FROM catalogue_image WHERE image_key = ?`).get(imageKey) as CatalogueImage | undefined;
        if (!existing) return reply.status(404).send({ message: 'Image not found' });

        const oldPath = path.join(UPLOAD_DIR, path.basename(existing.image_url));
        fs.unlink(oldPath, () => {});

        db.prepare(`DELETE FROM catalogue_image WHERE image_key = ?`).run(imageKey);
        return { ok: true };
    });

    // POST /api/catalogue/reorder
    app.post('/api/catalogue/reorder', async (req: FastifyRequest<{ Body: { items: { imageKey: string; order: number }[] } }>, reply: FastifyReply) => {
        const { items } = req.body;
        if (!Array.isArray(items)) return reply.status(400).send({ message: 'items must be an array' });

        const update = db.prepare(`UPDATE catalogue_image SET image_order = ? WHERE image_key = ?`);
        const updateAll = db.transaction((rows: { imageKey: string; order: number }[]) => {
            for (const row of rows) update.run(row.order, row.imageKey);
        });
        updateAll(items);

        return { ok: true };
    });
}