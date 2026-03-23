# Deployment Guide — Secure File Transfer

## What you need

- Your Proxmox server (192.168.1.30) with Docker + Docker Compose installed
- SSH access to the server
- Tailscale running on both the server and your devices

## Step 1: Copy files to the server

From your Arch desktop, copy the project folder to your Proxmox server:

```bash
scp -r /home/yousdje/Desktop/appbuild/secure-file-transfer/ user@192.168.1.30:~/secure-file-transfer/
```

Replace `user` with your SSH username on the Proxmox server.

## Step 2: SSH into the server

```bash
ssh user@192.168.1.30
cd ~/secure-file-transfer
```

## Step 3: Create the input/output directories

```bash
mkdir -p input output
```

- `input/` — files you want to share (mounted read-only in the container)
- `output/` — files received via transfers (mounted read-write)

## Step 4: Build and start

```bash
docker-compose up -d --build
```

That's it. The server is now running.

## Step 5: Verify it works

```bash
# Check container is running
docker-compose ps

# Check health endpoint
curl http://localhost:8080/health
# Should return: {"status": "ok", "version": "2.0"}

# Check metrics
curl http://localhost:8080/metrics

# Check logs
docker-compose logs -f
```

## How to use it

### From iPhone/iPad/Android (any browser)

1. Open Safari or Chrome
2. Go to `http://192.168.1.30:8080` (LAN) or `http://daggertooth-daggertooth.ts.net:8080` (Tailscale)
3. Tap "Add to Home Screen" for app-like experience
4. **Send**: tap "Send" tab, select file, share the 8-digit code
5. **Receive**: tap "Receive" tab, enter the 8-digit code

### From Windows/Linux/macOS (CLI)

```bash
# Install dependencies (one time)
pip install cryptography requests

# Send a file
python client.py send /path/to/file.pdf --server http://192.168.1.30:8080

# Receive a file (using the 8-digit code from the sender)
python client.py receive 12345678 --server http://192.168.1.30:8080
```

### From Linux without GUI

```bash
# Direct P2P transfer (no server needed, both machines need the script)
# On sender machine:
python cli.py send /path/to/file.txt --port 9999

# On receiver machine:
python cli.py receive 12345678 --host sender-ip --port 9999
```

## Running tests (optional)

```bash
# Build and run the test suite in Docker
docker build --target test -t secure-transfer-test .
docker run --rm secure-transfer-test
```

## Common commands

```bash
# View logs
docker-compose logs -f

# Restart
docker-compose restart

# Stop
docker-compose down

# Rebuild after changes
docker-compose up -d --build

# Check resource usage
docker stats secure-file-transfer
```

## Tailscale access from outside your LAN

If Tailscale is running on the server, all your Tailscale-connected devices can reach it at:

```
http://daggertooth-daggertooth.ts.net:8080
```

No port forwarding or firewall rules needed.

## Environment variables (optional)

Set these in `docker-compose.yml` under `environment:` if needed:

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Logging level: DEBUG, INFO, WARNING, ERROR |
| `LOG_FORMAT` | `json` | Log format: `json` (structured) or `text` (human-readable) |

## Troubleshooting

**Container won't start?**
```bash
docker-compose logs
```

**Can't connect from phone?**
- Make sure phone is on the same LAN, or connected via Tailscale
- Check firewall: `sudo ufw allow 8080/tcp` (if ufw is active)

**Transfer fails?**
- Check logs: `docker-compose logs -f`
- Try a small test file first
- Verify both devices can reach http://server-ip:8080/health

**Rate limited?**
- Wait 60 seconds and try again (max 5 pairing attempts per minute per IP)
