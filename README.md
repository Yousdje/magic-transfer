# MagicTransfer

Zero-knowledge encrypted file and text sharing. The server never sees your data.

## How it works

1. **Upload**: Your browser encrypts the file locally using AES-256-GCM before uploading
2. **Share**: You get a link containing the decryption key in the URL fragment (`#`)
3. **Download**: The recipient's browser decrypts everything locally
4. **Burn**: The encrypted blob is deleted after download (single-use)

The server stores only encrypted blobs. It never sees plaintext, filenames, or encryption keys.

## Tech Stack

- **Server**: Python / aiohttp (blob store with auth)
- **Crypto**: Web Crypto API (HKDF-SHA-256 + AES-256-GCM)
- **Deployment**: Docker + Cloudflare Tunnel

## Self-Hosting

```bash
docker compose up -d --build
```

Then set up a Cloudflare Tunnel pointing to `localhost:8080`.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 8080 | Listen port |
| `MAX_UPLOAD_BYTES` | 524288000 (500MB) | Max encrypted blob size |
| `MAX_TEXT_BYTES` | 204800 (200KB) | Max encrypted text size |
| `SESSION_TTL_MINUTES` | 60 | Session expiry |
| `MAX_SESSIONS` | 200 | Max concurrent sessions |
| `LOG_LEVEL` | INFO | Logging level |
| `LOG_FORMAT` | json | `json` or `text` |

## Security

See [SECURITY.md](SECURITY.md) for the full threat model and cryptographic details.
