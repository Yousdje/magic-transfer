# MagicTransfer Deployment Guide

## Requirements

- Docker + Docker Compose
- A domain name (~$10/year)
- Cloudflare account (free)

## Steps

### 1. Build and run

```bash
cd /path/to/magic-transfer
docker compose up -d --build
```

The service runs on port 8080 internally.

### 2. Set up Cloudflare Tunnel

1. Add your domain to Cloudflare (free plan)
2. Install `cloudflared` or add it as a Docker sidecar
3. Create a tunnel: `cloudflared tunnel create magictransfer`
4. Configure the tunnel to route your domain to `http://localhost:8080`
5. Cloudflare handles TLS automatically

### 3. Verify

- Visit `https://yourdomain.com` — should see the MagicTransfer UI
- Upload a test file, copy the link, open in another browser
- Verify the file downloads correctly
