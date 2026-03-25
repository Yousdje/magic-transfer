# MagicTransfer Architecture

## Overview

MagicTransfer is a zero-knowledge encrypted file and text sharing service. All encryption happens in the browser — the server is a simple encrypted blob store.

## Components

### Server (Python/aiohttp)
- `server.py` — single-file application
- Stores encrypted blobs on disk, encrypted text in memory
- Verifies auth tokens (HKDF-derived) without knowing the encryption key
- Session management with auto-expiry and burn-after-read
- Prometheus-compatible metrics at `/metrics`

### Client (Browser JavaScript)
- Web Crypto API for all cryptographic operations
- HKDF-SHA-256 key derivation from 256-bit IKM
- AES-256-GCM chunked file encryption (64KB chunks)
- Inline in `server.py` (no external JS dependencies)

### Deployment
- Docker container (non-root, capability-dropped)
- Cloudflare Tunnel for public access (TLS + DDoS protection)
- Self-hosted on Proxmox

## Data Flow

### Upload
```
Browser: generate IKM -> derive keys -> encrypt file -> encrypt metadata
         |
Server:  store encrypted blob to disk, save auth_token + encrypted_meta
         |
Browser: display share URL with IKM in fragment (#)
```

### Download
```
Browser: read IKM from URL fragment -> derive keys -> fetch info
         |
Server:  verify auth_token -> stream encrypted blob
         |
Browser: decrypt blob -> trigger file download -> call /api/complete
         |
Server:  delete encrypted blob from disk (burn-after-read)
```

## Routes

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/` | No | Home page |
| GET | `/d/{file_id}` | No | Download page |
| POST | `/api/upload` | No* | Upload encrypted blob |
| POST | `/api/text` | No* | Store encrypted text |
| GET | `/api/info/{file_id}` | Bearer | Get content type + encrypted metadata |
| GET | `/api/download/{file_id}` | Bearer | Stream encrypted blob |
| GET | `/api/text/{file_id}` | Bearer | Get encrypted text |
| POST | `/api/complete/{file_id}` | Bearer | Burn after read |
| GET | `/health` | No | Health check |
| GET | `/metrics` | No | Prometheus metrics |

*Upload/text endpoints are protected by per-IP rate limiting.

## Security Layers

1. **Zero-knowledge crypto** — server never sees plaintext or keys
2. **CSP with nonces** — prevents XSS/script injection
3. **Rate limiting** — per-IP on uploads and downloads
4. **Burn-after-read** — single-use transfers
5. **Session TTL** — auto-expire after 1 hour
6. **Docker hardening** — non-root, no-new-privileges, CAP_DROP ALL
