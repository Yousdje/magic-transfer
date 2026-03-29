# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Run all tests
pytest test_server.py -v

# Run a single test
pytest test_server.py::test_health -v

# Build Docker image
docker build --target production -t magic-transfer:latest .

# Run with Docker Compose
docker compose up -d --build

# Run tests inside Docker (mirrors CI)
docker build --target test -t magic-transfer:test . && docker run --rm magic-transfer:test
```

## Architecture

The entire application lives in `server.py` (~1500 lines) — both backend and frontend are embedded in a single file. There are no separate frontend build steps or assets.

**Backend (Python/aiohttp):**
- `BlobStore` — in-memory session registry + disk storage (`/output/uploads/`). Handles TTL expiry, orphan cleanup, and per-IP rate limiting.
- `RateLimiter` — sliding window limiter (10 uploads/min, 30 downloads/min per IP).
- Security middleware injects per-request CSP nonces, HSTS, X-Frame-Options, etc.

**Frontend (embedded in `server.py`):**
- Vanilla JS using only the Web Crypto API — no external JS libraries.
- Two pages: upload (`/`) and download (`/d/{file_id}`).
- The HTML/CSS/JS strings are defined near the bottom of `server.py` and served inline.

## Zero-Knowledge Design

The server never sees plaintext, keys, or filenames. The encryption key (IKM) is generated in the browser and shared only via the URL fragment (`#`), which is never sent to the server per RFC 3986.

**Crypto flow:**
1. Browser generates 256-bit IKM with `crypto.getRandomValues()`
2. HKDF-SHA-256 derives three domain-separated keys: `fileKey`, `metaKey`, `authKey`
3. File encrypted in 64KB chunks with AES-256-GCM (deterministic IVs: base nonce XOR chunk index)
4. Upload sends only ciphertext + encrypted metadata + auth token
5. Share URL: `/d/{file_id}#{base64url(ikm)}` — fragment never reaches server

**Burn-after-read:** After successful download, browser calls `POST /api/complete/{file_id}`, which deletes the encrypted blob from disk.

## Key Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Listening port |
| `MAX_UPLOAD_BYTES` | 500MB | Max file size |
| `MAX_TEXT_BYTES` | 200KB | Max text size |
| `SESSION_TTL_MINUTES` | `60` | Session expiry |
| `MAX_SESSIONS` | `200` | Concurrent sessions cap |
| `METRICS_TOKEN` | unset | Enables `/metrics` endpoint |
| `LOG_FORMAT` | `json` | `json` or `text` |

## API Routes

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/upload` | Rate-limited | Upload encrypted file blob |
| POST | `/api/text` | Rate-limited | Store encrypted text |
| GET | `/api/info/{file_id}` | Bearer authToken | Fetch encrypted metadata + blob size |
| GET | `/api/download/{file_id}` | Bearer authToken | Stream encrypted blob |
| GET | `/api/text/{file_id}` | Bearer authToken | Fetch encrypted text |
| POST | `/api/complete/{file_id}` | Bearer authToken | Burn-after-read (delete session + file) |
| GET | `/health` | None | Health check |
| GET | `/metrics` | Bearer METRICS_TOKEN | Prometheus-format metrics |

## Testing Notes

Tests in `test_server.py` use `pytest-aiohttp` with mock encrypted payloads (real crypto runs in the browser). The `pytest.ini` sets `asyncio_mode = auto`. Tests cover upload/download flow, auth enforcement, burn-after-read, rate limiting, and all security headers.
