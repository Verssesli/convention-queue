# Convention Queue

A mobile-first virtual queue + live catalogue system for convention artists.

## Structure

```
convention-queue/
├── frontend/
│   ├── index.html      ← Customer-facing (queue + catalogue)
│   └── artist.html     ← Artist panel (password-gated)
├── backend/
│   ├── src/
│   │   ├── server.ts
│   │   ├── db/
│   │   │   ├── database.ts
│   │   │   └── migrate.ts
│   │   └── routes/
│   │       ├── queue.ts
│   │       └── catalogue.ts
│   ├── package.json
│   ├── tsconfig.json
│   └── .env.example
└── uploads/            ← Auto-created; stores catalogue images
```

## Quick Start

```bash
cd backend
cp .env.example .env
# Edit .env — set ARTIST_PASSWORD to something strong

npm install
npm run dev
```

The server starts on http://localhost:3000.
- Customer queue: http://localhost:3000/
- Artist panel:   http://localhost:3000/artist

## Production Build

```bash
npm run build
npm start
```

## Environment Variables

| Variable               | Default            | Description                          |
|------------------------|--------------------|--------------------------------------|
| ARTIST_PASSWORD        | (required)         | Password for the artist panel        |
| PORT                   | 3000               | Server port                          |
| HOST                   | 0.0.0.0            | Bind address                         |
| ACCESS_WINDOW_MINUTES  | 30                 | Minutes users have after being called|
| DB_PATH                | ./data/queue.db    | SQLite database file path            |
| UPLOAD_DIR             | ./uploads          | Where catalogue images are stored    |
| UPLOAD_BASE_URL        | /uploads           | Public URL prefix for images         |
| FRONTEND_DIR           | ../frontend        | Path to compiled frontend files      |
| CORS_ORIGIN            | * (all)            | Restrict in production               |

## API Reference

All artist endpoints require the header `X-Artist-Password: <password>`.

### Public Queue

| Method | Endpoint                          | Body / Query              |
|--------|-----------------------------------|---------------------------|
| POST   | /api/queue/join                   | `{}`                      |
| GET    | /api/queue/status?queueId=...     | query param               |
| POST   | /api/queue/leave                  | `{ queueId }`             |
| POST   | /api/queue/requeue                | `{ queueId }`             |

### Public Catalogue

| Method | Endpoint            |
|--------|---------------------|
| GET    | /api/catalogue      |

### Artist — Queue

| Method | Endpoint            | Body                |
|--------|---------------------|---------------------|
| GET    | /api/artist/queue   | —                   |
| POST   | /api/artist/allow   | `{ count: number }` |

### Artist — Catalogue

| Method | Endpoint                   | Body / Form                         |
|--------|----------------------------|-------------------------------------|
| POST   | /api/catalogue/upload      | `multipart: file`                   |
| PUT    | /api/catalogue/replace     | `multipart: imageKey, file`         |
| DELETE | /api/catalogue/remove      | `{ imageKey }`                      |
| POST   | /api/catalogue/reorder     | `{ items: [{ imageKey, order }] }`  |

## Notes

- Queue IDs are UUIDv4 (RFC 4122).
- Queue numbers are sequential integers (001, 002, …).
- `ACCESS_WINDOW_MINUTES` applies globally; set it once before the event starts.
- The artist panel password is sent as a request header — use HTTPS in production.
- Upload size limit is 20 MB per image (configurable in server.ts).