# 🤖 Claude Code Handoff - Secure File Transfer

## Project Overview
Universal secure file transfer system met E2E encryption voor iOS, Android, Windows, Linux.

## What Needs to be Done

### Priority 1: Security Review & Hardening
- [ ] Review cryptographic implementation (AES-256-GCM, PBKDF2)
- [ ] Check for common vulnerabilities (injection, path traversal, etc)
- [ ] Audit Docker security settings
- [ ] Review network exposure and firewall rules
- [ ] Test error handling and edge cases

### Priority 2: Production Optimizations
- [ ] Add proper logging (structured, levels)
- [ ] Implement rate limiting for API endpoints
- [ ] Add request timeouts and connection limits
- [ ] Optimize large file transfers (chunking strategy)
- [ ] Add metrics/monitoring endpoints (Prometheus?)

### Priority 3: Testing
- [ ] Write unit tests for crypto functions
- [ ] Integration tests for file transfers
- [ ] Test cross-platform compatibility
- [ ] Load testing for concurrent transfers
- [ ] Security testing (fuzzing, penetration tests)

### Priority 4: Nice-to-Haves
- [ ] Add progress indicators for large files
- [ ] Implement file compression option
- [ ] Add transfer queue/history
- [ ] WebSocket real-time updates
- [ ] Resume interrupted transfers

## Current Architecture

```
┌─────────────────────────────────┐
│  Docker Server (Proxmox)        │
│  - REST API (aiohttp)           │
│  - WebSocket support            │
│  - E2E Encryption               │
│  - Port: 8080                   │
│  - IP: 192.168.1.30            │
└──────────────┬──────────────────┘
               │
      ┌────────┴────────┐
      │                 │
  ┌───▼────┐      ┌────▼────┐
  │ Mobile │      │ Desktop │
  │ (PWA)  │      │  (CLI)  │
  └────────┘      └─────────┘
```

## Key Files

**Server:**
- `server.py` - Main server application (REST API + WebSocket)
- `Dockerfile` - Container configuration
- `docker-compose.yml` - Deployment configuration

**Clients:**
- `client.py` - Universal CLI client (Python)
- Web UI - Embedded in server.py (PWA-ready)

**Documentation:**
- `SECURITY.md` - Current security analysis
- `TAILSCALE.md` - Tailscale-specific setup
- `INSTALL.md` - Platform installation guides

## Specific User Setup

**Tailscale Domain:** `daggertooth-daggertooth.ts.net`
**Server IP:** `192.168.1.30:8080`

**User's Devices:**
- iPhone/iPad (iOS)
- Android phone
- Windows 10/11
- Arch Linux desktop
- Various Linux servers (some without GUI)

## Security Requirements

**Current Implementation:**
- AES-256-GCM encryption (AEAD)
- PBKDF2 key derivation (100,000 iterations, SHA-256)
- SHA-256 file integrity verification
- 6-digit pairing codes (cryptographically random)
- Unique nonces per chunk

**Questions to Address:**
1. Is 6-digit pairing code sufficient? (10^6 combinations)
2. Should we add rate limiting on pairing attempts?
3. Is session timeout (1 hour) appropriate?
4. Should we implement perfect forward secrecy?
5. Any timing attack vulnerabilities in crypto operations?

## Known Limitations

1. **Pairing Code Entropy**: 6 digits = ~20 bits, brute-forceable
2. **No Rate Limiting**: API endpoints can be hammered
3. **No Logging**: Hard to debug production issues
4. **No Metrics**: Can't monitor performance/usage
5. **Single Server**: No load balancing or redundancy
6. **Memory Usage**: Large files loaded in chunks but not optimized
7. **No Tests**: Zero test coverage

## Development Environment

```bash
# Install dependencies
pip install aiohttp cryptography aiofiles requests

# Run server locally
python server.py

# Test client
python client.py send test.txt --server http://localhost:8080
python client.py receive 123456
```

## Testing Checklist

### Manual Tests
- [ ] Send file between different platforms
- [ ] Large file (>1GB) transfer
- [ ] Concurrent transfers (multiple sessions)
- [ ] Invalid pairing code handling
- [ ] Network interruption during transfer
- [ ] Hash mismatch detection
- [ ] Session expiration

### Security Tests
- [ ] SQL injection attempts (N/A - no SQL)
- [ ] Path traversal in filenames
- [ ] XSS in web interface
- [ ] CSRF protection (check for state-changing GETs)
- [ ] Timing attacks on pairing code validation
- [ ] Memory exhaustion (huge files)
- [ ] Replay attacks (nonce reuse)

## Deployment Target

**Production Environment:**
- Proxmox host (Ubuntu/Debian based)
- Docker 24.x
- Docker Compose 2.x
- Tailscale for VPN access
- Behind UniFi UXG-Max gateway

**Resource Constraints:**
- Shared host (other services running)
- ~2GB RAM available
- 100Mbit/1Gbit network (LAN)

## Questions for Claude Code

1. **Security**: What are the top 3 security concerns?
2. **Performance**: How to optimize for 10+ concurrent transfers?
3. **Reliability**: What error cases are not handled?
4. **Testing**: What tests are most critical?
5. **Monitoring**: What metrics should we track?

## Suggested Approach

1. **First Pass**: Security audit of crypto implementation
2. **Second Pass**: Add logging and error handling
3. **Third Pass**: Implement rate limiting
4. **Fourth Pass**: Write critical tests
5. **Fifth Pass**: Performance optimization

## Success Criteria

✅ **Must Have:**
- No critical security vulnerabilities
- Handles network failures gracefully
- Works reliably for files up to 10GB
- Proper logging for debugging
- Rate limiting to prevent abuse

✅ **Nice to Have:**
- Unit test coverage >80%
- Performance metrics/monitoring
- Graceful degradation under load
- Comprehensive documentation

## How to Start with Claude Code

```bash
# Navigate to project
cd /path/to/secure-file-transfer

# Start Claude Code
claude

# Or specific tasks:
claude "Review security of server.py focusing on cryptography"
claude "Add structured logging to server.py"
claude "Write unit tests for encryption functions"
claude "Implement rate limiting middleware"
```

## Contact Points

If Claude Code needs clarification:
- **User**: Youssef
- **Use Case**: Personal file sharing between devices
- **Threat Model**: Trusted network (LAN + Tailscale VPN)
- **Expected Load**: <10 concurrent transfers, <100 daily transfers

## Notes

- This is for personal use, not commercial
- Security is important but doesn't need to be bank-grade
- Usability matters - should be easy for non-technical family members
- Performance: 10Mbit+ transfer speeds acceptable
- Availability: 99% uptime acceptable (home lab)

---

## Quick Commands for Claude Code

```bash
# Review security
claude code review --focus security server.py

# Add feature
claude "Add rate limiting to API endpoints in server.py"

# Write tests
claude "Generate pytest unit tests for client.py"

# Optimize
claude "Optimize large file handling in server.py for memory efficiency"

# Fix issues
claude "Fix all TODO and FIXME comments in codebase"
```

Ready to hand off! 🚀
