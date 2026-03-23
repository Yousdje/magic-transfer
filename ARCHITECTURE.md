# Universal Secure File Transfer
# Cross-platform architecture voor iOS, Android, Windows, Linux

## Architectuur Overview

```
┌─────────────────────────────────────────────────┐
│         Docker Container (Proxmox)              │
│  ┌───────────────────────────────────────────┐  │
│  │   Secure Transfer Server                   │  │
│  │   - REST API                               │  │
│  │   - WebSocket support                      │  │
│  │   - E2E Encryption orchestration           │  │
│  │   - Session management                     │  │
│  └───────────────────────────────────────────┘  │
└─────────────────────────────────────────────────┘
                       ▲
                       │ HTTPS/WSS
        ┌──────────────┼──────────────┐
        │              │              │
┌───────▼──────┐ ┌────▼─────┐ ┌──────▼──────┐
│   iOS App    │ │ Android  │ │  Web Client │
│  (Native)    │ │  (Native)│ │(iOS/Android)│
└──────────────┘ └──────────┘ └─────────────┘
        │              │              │
┌───────▼──────────────▼──────────────▼──────┐
│            Windows / Linux                  │
│  - CLI client (Python)                      │
│  - Web browser (GUI)                        │
│  - Electron app (optional)                  │
└─────────────────────────────────────────────┘
```

## Components

### 1. Central Server (Docker)
- REST API voor file metadata
- WebSocket voor real-time signaling
- Draait op je Proxmox
- Toegankelijk via Tailscale

### 2. Web Client (Universal)
- Works on ALL devices met browser
- Progressive Web App (PWA)
- iOS Safari compatible
- Android Chrome compatible
- Desktop browsers
- Can be "installed" as app

### 3. Native CLI
- Python-based
- Works on Linux/Windows/macOS
- No GUI needed
- Scriptable

### 4. Native Apps (Optional)
- iOS: Swift app
- Android: Kotlin app
- Better UX than web
- Background transfers

## Access Methods

| Device | Method 1 (Best) | Method 2 | Method 3 |
|--------|-----------------|----------|----------|
| iOS | Web App (PWA) | Safari | Native app* |
| Android | Web App (PWA) | Chrome | Native app* |
| Windows | Web browser | CLI | Desktop app* |
| Arch Linux | CLI | Web browser | - |
| Linux (no GUI) | CLI | - | - |

*Native apps = future enhancement

## Installation per Platform

### Server (Proxmox Docker)
```bash
docker-compose up -d
# Access: https://transfer.tailnet-name.ts.net
```

### iOS/Android (Web App)
```
1. Open Safari/Chrome
2. Navigate to: https://your-server:8080
3. Tap "Share" → "Add to Home Screen"
4. Now works like native app!
```

### Windows/Linux (CLI)
```bash
pip install cryptography requests websockets
./client.py send file.txt
./client.py receive
```

### Linux (no GUI)
```bash
# Same as above, pure terminal
./client.py send /data/backup.tar.gz
```

## Key Features

### Cross-Platform
✅ Single server, multiple clients
✅ Same pairing code system
✅ Works everywhere

### Progressive Enhancement
- Basic: Web browser (works everywhere)
- Better: PWA (app-like experience)
- Best: Native apps (future)

### Offline First
- Server can be offline
- P2P fallback (when both online)
- Queue transfers

### Network Agnostic
- LAN (direct)
- Tailscale VPN
- WAN (with relay server)
