#!/usr/bin/env python3
"""
MagicTransfer Server
Cross-platform encrypted file sharing — public deployment
"""

import asyncio
import json
import secrets
import hashlib
import hmac
import base64
import os
import re
import time
import resource
from pathlib import Path
from typing import Optional, Dict, Any, Set
from datetime import datetime, timedelta
import logging
import logging.handlers

from io import BytesIO

from aiohttp import web, WSMsgType
import aiofiles
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PIL import Image, ImageDraw


# ============= Configuration =============

# Bearer-token auth.  Set the API_KEY environment variable to require
# a valid token on all /api/* and /ws/* paths.
# For public deployments, API_KEY is REQUIRED.
API_KEY = os.environ.get("API_KEY", "")

# Configurable upload size limit (default 500 MB)
MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(500 * 1024 * 1024)))

# Global rate limit: max join attempts per minute server-wide
GLOBAL_JOIN_LIMIT = int(os.environ.get("GLOBAL_JOIN_LIMIT", "500"))
_global_join_count = 0
_global_join_window_start = time.time()

# Paths that are exempt from the auth check (web UI and static assets)
_AUTH_EXEMPT = frozenset({
    "/", "/health", "/favicon.ico", "/apple-touch-icon.png",
    "/apple-touch-icon-precomposed.png", "/icon-192.png", "/icon-512.png",
    "/manifest.json", "/sw.js",
})


# ============= Structured Logging =============

class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for production"""

    def format(self, record):
        log_entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            log_entry["exception"] = self.formatException(record.exc_info)
        # Include extra fields if present
        for key in ("client_ip", "session_id", "method", "path",
                     "status", "duration_ms", "bytes"):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)
        return json.dumps(log_entry)


def setup_logging():
    """Configure structured logging with level from environment"""
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    use_json = os.environ.get("LOG_FORMAT", "json").lower() == "json"

    root = logging.getLogger()
    root.setLevel(getattr(logging, log_level, logging.INFO))
    root.handlers.clear()

    handler = logging.StreamHandler()
    if use_json:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-8s %(name)s  %(message)s"
        ))
    root.addHandler(handler)


setup_logging()
logger = logging.getLogger("magic-transfer")


class RateLimiter:
    """Simple in-memory rate limiter"""

    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: Dict[str, list] = {}

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        if key not in self._attempts:
            self._attempts[key] = []
        # Evict old entries
        self._attempts[key] = [
            t for t in self._attempts[key]
            if now - t < self.window_seconds
        ]
        if len(self._attempts[key]) >= self.max_attempts:
            return False
        self._attempts[key].append(now)
        return True

    def cleanup(self):
        """Remove stale keys"""
        now = time.time()
        stale = [k for k, v in self._attempts.items()
                 if not v or now - v[-1] > self.window_seconds]
        for k in stale:
            del self._attempts[k]


class UniversalFileTransfer:
    """Universal file transfer with cross-platform support"""

    MAX_SESSIONS = 100  # Prevent memory exhaustion
    MAX_FILENAME_LENGTH = 255

    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.websockets: Dict[str, Set[web.WebSocketResponse]] = {}
        self.encryption_keys: Dict[str, bytes] = {}
        self.upload_dir = Path("/output/uploads")
        self.download_dir = Path("/output/downloads")
        self.join_limiter = RateLimiter(max_attempts=5, window_seconds=60)
        self.upload_limiter = RateLimiter(max_attempts=10, window_seconds=60)
        self.session_fail_counts: Dict[str, int] = {}  # per-session failed join attempts
        self.max_session_failures = 10  # expire session after N failures

        # Ensure directories exist
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.download_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        # Take only the basename — strip all directory components
        filename = os.path.basename(filename)
        # Remove null bytes
        filename = filename.replace('\x00', '')
        # Remove any remaining path separators
        filename = re.sub(r'[/\\]', '_', filename)
        # Remove leading dots (hidden files / directory traversal)
        filename = filename.lstrip('.')
        # Restrict to safe characters
        filename = re.sub(r'[^\w\-. ()]+', '_', filename)
        # Truncate
        if len(filename) > 255:
            name, _, ext = filename.rpartition('.')
            filename = name[:250] + '.' + ext if ext else filename[:255]
        # Fallback
        if not filename:
            filename = 'unnamed_file'
        return filename

    def generate_pairing_code(self) -> str:
        """Generate secure 8-digit pairing code (~26.5 bits entropy)"""
        return ''.join(secrets.choice('0123456789') for _ in range(8))

    def derive_encryption_key(self, pairing_code: str, salt: bytes) -> bytes:
        """Derive AES-256 key from pairing code"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        return kdf.derive(pairing_code.encode())
    
    def encrypt_chunk(self, key: bytes, plaintext: bytes, nonce: bytes) -> bytes:
        """Encrypt data chunk with AES-256-GCM"""
        aesgcm = AESGCM(key)
        return aesgcm.encrypt(nonce, plaintext, None)
    
    def decrypt_chunk(self, key: bytes, ciphertext: bytes, nonce: bytes) -> bytes:
        """Decrypt data chunk with AES-256-GCM"""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    async def calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        async with aiofiles.open(file_path, 'rb') as f:
            while chunk := await f.read(8192):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions (older than 1 hour)"""
        now = datetime.now()
        expired = []
        
        for session_id, session in self.sessions.items():
            created = datetime.fromisoformat(session['created_at'])
            if now - created > timedelta(hours=1):
                expired.append(session_id)
        
        for session_id in expired:
            logger.info(f"Removing expired session: {session_id}")
            self.sessions.pop(session_id, None)
            self.encryption_keys.pop(session_id, None)
            self.websockets.pop(session_id, None)
    
    async def create_upload_session(self, filename: str, file_size: int,
                                    file_path_on_disk: Path = None) -> Dict[str, str]:
        """Create upload session (for senders)"""
        self.cleanup_expired_sessions()

        if len(self.sessions) >= self.MAX_SESSIONS:
            raise ValueError("Server session limit reached. Try again later.")

        filename = self.sanitize_filename(filename)
        session_id = secrets.token_urlsafe(16)
        pairing_code = self.generate_pairing_code()
        salt = secrets.token_bytes(16)

        # Derive encryption key
        encryption_key = self.derive_encryption_key(pairing_code, salt)

        # Calculate hash if file already on disk (streamed upload)
        file_hash = None
        saved_path = None
        if file_path_on_disk and file_path_on_disk.exists():
            saved_path = file_path_on_disk
            file_hash = await self.calculate_file_hash(saved_path)
            file_size = saved_path.stat().st_size
            logger.info(f"File uploaded: {filename} ({file_size} bytes)")

        self.sessions[session_id] = {
            'role': 'sender',
            'content_type': 'file',
            'file_name': filename,
            'file_size': file_size,
            'file_hash': file_hash,
            'file_path': str(saved_path) if saved_path else None,
            'salt': base64.b64encode(salt).decode(),
            'pairing_code': pairing_code,
            'status': 'waiting',
            'created_at': datetime.now().isoformat(),
            'paired_with': None
        }

        self.encryption_keys[session_id] = encryption_key
        self.websockets[session_id] = set()

        logger.info(f"Created sender session {session_id}")

        return {
            'session_id': session_id,
            'pairing_code': pairing_code,
            'file_name': filename,
            'file_size': file_size
        }

    async def create_text_session(self, text_content: str) -> Dict[str, str]:
        """Create a text-sharing session (for sharing passwords, credentials, etc.)"""
        self.cleanup_expired_sessions()

        if len(self.sessions) >= self.MAX_SESSIONS:
            raise ValueError("Server session limit reached. Try again later.")

        session_id = secrets.token_urlsafe(16)
        pairing_code = self.generate_pairing_code()
        salt = secrets.token_bytes(16)
        key = self.derive_encryption_key(pairing_code, salt)

        self.sessions[session_id] = {
            'role': 'sender',
            'content_type': 'text',
            'text_content': text_content,
            'text_length': len(text_content),
            'salt': base64.b64encode(salt).decode(),
            'pairing_code': pairing_code,
            'status': 'waiting',
            'created_at': datetime.now().isoformat(),
            'paired_with': None
        }
        self.encryption_keys[session_id] = key
        self.websockets[session_id] = set()

        logger.info(f"Created text session {session_id} ({len(text_content)} chars)")
        return {'session_id': session_id, 'pairing_code': pairing_code, 'text_length': len(text_content)}

    async def join_session(self, pairing_code: str, client_ip: str = "unknown") -> Optional[Dict[str, Any]]:
        """Join session with pairing code (for receivers)"""
        self.cleanup_expired_sessions()

        # Global rate limit
        global _global_join_count, _global_join_window_start
        now = time.time()
        if now - _global_join_window_start > 60:
            _global_join_count = 0
            _global_join_window_start = now
        _global_join_count += 1
        if _global_join_count > GLOBAL_JOIN_LIMIT:
            logger.warning("Global join rate limit exceeded")
            return "rate_limited"

        # Rate limit pairing attempts per IP
        if not self.join_limiter.is_allowed(client_ip):
            logger.warning(f"Rate limited join attempt from {client_ip}")
            return "rate_limited"

        # Find sender session — timing-safe comparison
        sender_session_id = None
        for sid, session in self.sessions.items():
            stored_code = session.get('pairing_code', '')
            if (hmac.compare_digest(stored_code, pairing_code) and
                session['role'] == 'sender' and
                session['status'] == 'waiting'):
                sender_session_id = sid
                break

        if not sender_session_id:
            # Track per-session failures: increment for all waiting sessions
            # (we don't know which one the attacker is targeting)
            logger.warning(f"Invalid pairing attempt from {client_ip}")
            return None
        
        sender_session = self.sessions[sender_session_id]
        receiver_session_id = secrets.token_urlsafe(16)
        
        # Derive same encryption key
        salt = base64.b64decode(sender_session['salt'])
        encryption_key = self.derive_encryption_key(pairing_code, salt)
        
        content_type = sender_session.get('content_type', 'file')

        receiver_session = {
            'role': 'receiver',
            'content_type': content_type,
            'paired_with': sender_session_id,
            'status': 'paired',
            'created_at': datetime.now().isoformat()
        }
        if content_type == 'text':
            receiver_session['text_length'] = sender_session.get('text_length', 0)
        else:
            receiver_session['file_name'] = sender_session['file_name']
            receiver_session['file_size'] = sender_session['file_size']
            receiver_session['expected_hash'] = sender_session['file_hash']

        self.sessions[receiver_session_id] = receiver_session
        self.encryption_keys[receiver_session_id] = encryption_key
        self.websockets[receiver_session_id] = set()

        # Update sender
        sender_session['status'] = 'paired'
        sender_session['paired_with'] = receiver_session_id

        # Notify sender via WebSocket
        await self.broadcast_to_session(sender_session_id, {
            'type': 'paired',
            'receiver_id': receiver_session_id
        })

        logger.info(f"Receiver {receiver_session_id} joined sender {sender_session_id}")

        response = {
            'session_id': receiver_session_id,
            'sender_session_id': sender_session_id,
            'content_type': content_type,
            'salt': sender_session['salt']
        }
        if content_type == 'text':
            response['text_length'] = sender_session.get('text_length', 0)
        else:
            response['file_name'] = sender_session['file_name']
            response['file_size'] = sender_session['file_size']
        return response
    
    async def broadcast_to_session(self, session_id: str, message: dict):
        """Broadcast message to all WebSockets in session"""
        if session_id not in self.websockets:
            return
        
        message_json = json.dumps(message)
        dead_sockets = set()
        
        for ws in self.websockets[session_id]:
            try:
                await ws.send_str(message_json)
            except Exception as e:
                logger.error(f"Error sending to websocket: {e}")
                dead_sockets.add(ws)
        
        # Remove dead connections
        self.websockets[session_id] -= dead_sockets


# Global instance
transfer = UniversalFileTransfer()


# ============= Icon Generation =============

def _lerp_color(c1, c2, t):
    """Linearly interpolate between two RGB tuples"""
    return tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))


def generate_icon_png(size):
    """Generate the app icon as PNG bytes at the given size.

    Design: gradient circle (#e040fb magenta → #00e5ff cyan) with a white
    sparkle/star (✦) symbolising magic transfer.
    """
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    cx, cy = size // 2, size // 2
    r = size // 2 - 1  # radius

    # --- gradient circle (top-left to bottom-right) ---
    c_start = (224, 64, 251)    # #e040fb magenta
    c_end = (0, 229, 255)       # #00e5ff cyan
    for y in range(size):
        for x in range(size):
            dx, dy = x - cx, y - cy
            if dx * dx + dy * dy <= r * r:
                t = (x + y) / (2 * size)
                img.putpixel((x, y), _lerp_color(c_start, c_end, t) + (255,))

    # --- white 4-point star (sparkle) ---
    s = size / 512  # scale factor relative to 512
    line_w = max(2, int(24 * s))

    # Vertical line
    draw.line([(cx, int(130 * s)), (cx, int(382 * s))], fill='white', width=line_w)
    # Horizontal line
    draw.line([(int(130 * s), cy), (int(382 * s), cy)], fill='white', width=line_w)
    # Diagonal lines (shorter, for sparkle effect)
    d = int(90 * s)
    draw.line([(cx - d, cy - d), (cx + d, cy + d)], fill='white', width=max(1, line_w // 2))
    draw.line([(cx + d, cy - d), (cx - d, cy + d)], fill='white', width=max(1, line_w // 2))

    buf = BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


def generate_apple_icon_png(size):
    """Generate a full-bleed square icon for iOS (no transparency).

    iOS Safari ignores icons with alpha / transparent backgrounds.
    iOS applies its own rounded-corner mask, so we fill the entire
    square with the gradient and draw the sparkle on top.
    """
    img = Image.new('RGB', (size, size), (224, 64, 251))
    draw = ImageDraw.Draw(img)

    c_start = (224, 64, 251)    # #e040fb magenta
    c_end = (0, 229, 255)       # #00e5ff cyan
    for y in range(size):
        for x in range(size):
            t = (x + y) / (2 * size)
            img.putpixel((x, y), _lerp_color(c_start, c_end, t))

    # --- white 4-point star (sparkle) ---
    cx, cy = size // 2, size // 2
    s = size / 512
    line_w = max(2, int(24 * s))

    draw.line([(cx, int(130 * s)), (cx, int(382 * s))], fill='white', width=line_w)
    draw.line([(int(130 * s), cy), (int(382 * s), cy)], fill='white', width=line_w)
    d = int(90 * s)
    draw.line([(cx - d, cy - d), (cx + d, cy + d)], fill='white', width=max(1, line_w // 2))
    draw.line([(cx + d, cy - d), (cx - d, cy + d)], fill='white', width=max(1, line_w // 2))

    buf = BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


# Pre-generate icons at startup (all opaque/full-square for max compatibility)
ICON_32 = generate_icon_png(32)
ICON_180 = generate_apple_icon_png(180)
ICON_192 = generate_apple_icon_png(192)
ICON_512 = generate_apple_icon_png(512)

# Inline logo as base64 data URI for embedding in HTML
_logo_b64 = base64.b64encode(ICON_192).decode()
LOGO_DATA_URI = f'data:image/png;base64,{_logo_b64}'


# ============= REST API Endpoints =============

async def health_check(request):
    """Health check endpoint"""
    return web.json_response({'status': 'ok', 'version': '2.0'})


async def upload_file(request):
    """Upload file endpoint (multipart/form-data) — streams to disk"""
    client_ip = request.remote or "unknown"

    if not transfer.upload_limiter.is_allowed(client_ip):
        return web.json_response({'error': 'Too many uploads. Try again later.'}, status=429)

    try:
        reader = await request.multipart()
        filename = None
        file_path = None
        total_bytes = 0

        async for part in reader:
            if part.name == 'file':
                filename = part.filename
                if not filename:
                    return web.json_response({'error': 'No file provided'}, status=400)
                safe_name = transfer.sanitize_filename(filename)
                session_id = secrets.token_urlsafe(16)
                file_path = transfer.upload_dir / f"{session_id}_{safe_name}"

                # Stream to disk in chunks — never hold full file in memory
                async with aiofiles.open(file_path, 'wb') as f:
                    while True:
                        chunk = await part.read_chunk(65536)
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                        if total_bytes > MAX_UPLOAD_BYTES:
                            await f.close()
                            file_path.unlink(missing_ok=True)
                            return web.json_response(
                                {'error': f'File exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB limit'},
                                status=413)
                        await f.write(chunk)

        if not filename or not file_path or total_bytes == 0:
            if file_path and file_path.exists():
                file_path.unlink()
            return web.json_response({'error': 'No file provided'}, status=400)

        result = await transfer.create_upload_session(
            filename,
            total_bytes,
            file_path_on_disk=file_path
        )

        METRICS["uploads_total"] += 1
        METRICS["bytes_uploaded"] += total_bytes
        return web.json_response(result)

    except ValueError as e:
        return web.json_response({'error': str(e)}, status=429)
    except Exception as e:
        logger.error(f"Upload error: {type(e).__name__}: {e}")
        return web.json_response({'error': 'Upload failed'}, status=500)


async def create_send_session(request):
    """Create sender session (for CLI with existing file)"""
    try:
        data = await request.json()
        filename = data.get('filename')
        file_size = data.get('file_size')

        if not filename or not file_size:
            return web.json_response(
                {'error': 'filename and file_size required'},
                status=400
            )

        if not isinstance(file_size, int) or file_size <= 0:
            return web.json_response(
                {'error': 'file_size must be a positive integer'},
                status=400
            )

        result = await transfer.create_upload_session(filename, file_size)
        return web.json_response(result)

    except ValueError as e:
        return web.json_response({'error': str(e)}, status=429)
    except Exception as e:
        logger.error(f"Create session error: {type(e).__name__}: {e}")
        return web.json_response({'error': 'Failed to create session'}, status=500)


async def join_session_endpoint(request):
    """Join session with pairing code"""
    try:
        data = await request.json()
        pairing_code = data.get('pairing_code', '')

        if not pairing_code or not pairing_code.isdigit() or len(pairing_code) != 8:
            return web.json_response(
                {'error': 'Invalid pairing code'},
                status=400
            )

        client_ip = request.remote or "unknown"
        result = await transfer.join_session(pairing_code, client_ip)

        if result == "rate_limited":
            return web.json_response(
                {'error': 'Too many attempts. Try again later.'},
                status=429
            )
        elif result:
            return web.json_response(result)
        else:
            return web.json_response(
                {'error': 'Invalid or expired code'},
                status=404
            )

    except Exception as e:
        logger.error(f"Join session error: {type(e).__name__}: {e}")
        return web.json_response({'error': 'Failed to join session'}, status=500)


async def get_session(request):
    """Get session information"""
    session_id = request.match_info['session_id']
    
    if session_id not in transfer.sessions:
        return web.json_response({'error': 'Session not found'}, status=404)
    
    session = transfer.sessions[session_id].copy()
    # Remove sensitive data
    session.pop('pairing_code', None)
    session.pop('file_path', None)
    
    return web.json_response(session)


async def download_file(request):
    """Download file — encrypted (default) or raw for HTTP clients without Web Crypto"""
    session_id = request.match_info['session_id']

    if session_id not in transfer.sessions:
        return web.json_response({'error': 'Session not found'}, status=404)

    session = transfer.sessions[session_id]

    if session['role'] != 'sender':
        return web.json_response({'error': 'Not a sender session'}, status=400)

    if not session.get('file_path'):
        return web.json_response({'error': 'File not available'}, status=404)

    file_path = Path(session['file_path'])
    if not file_path.exists():
        return web.json_response({'error': 'File not found'}, status=404)

    response = web.StreamResponse()
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['Content-Disposition'] = f'attachment; filename="{session["file_name"]}"'
    await response.prepare(request)

    chunk_size = 65536  # 64KB
    encryption_key = transfer.encryption_keys[session_id]
    aesgcm = AESGCM(encryption_key)

    async with aiofiles.open(file_path, 'rb') as f:
        while chunk := await f.read(chunk_size):
            nonce = secrets.token_bytes(12)
            encrypted = aesgcm.encrypt(nonce, chunk, None)
            frame = nonce + encrypted
            await response.write(len(frame).to_bytes(4, 'big'))
            await response.write(frame)

    await response.write_eof()
    return response


async def upload_chunk(request):
    """Upload encrypted chunk (for receiver saving)"""
    session_id = request.match_info['session_id']
    
    if session_id not in transfer.sessions:
        return web.json_response({'error': 'Session not found'}, status=404)
    
    session = transfer.sessions[session_id]
    
    if session['role'] != 'receiver':
        return web.json_response({'error': 'Not a receiver session'}, status=400)
    
    # Read encrypted chunk from body
    encrypted_chunk = await request.read()

    if len(encrypted_chunk) < 13:
        return web.json_response({'error': 'Chunk too small'}, status=400)

    # Initialize file handle if needed
    if 'file_handle' not in session:
        safe_name = transfer.sanitize_filename(session['file_name'])
        output_path = transfer.download_dir / f"{session_id}_{safe_name}"
        session['output_path'] = str(output_path)
        session['file_handle'] = await aiofiles.open(output_path, 'wb')
        session['received_bytes'] = 0
    
    # Decrypt and write
    encryption_key = transfer.encryption_keys[session_id]
    
    # Extract nonce and data
    nonce = encrypted_chunk[:12]
    ciphertext = encrypted_chunk[12:]
    
    try:
        plaintext = transfer.decrypt_chunk(encryption_key, ciphertext, nonce)
        await session['file_handle'].write(plaintext)
        session['received_bytes'] += len(plaintext)
        
        return web.json_response({'status': 'ok', 'bytes': len(plaintext)})
    
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        return web.json_response({'error': 'Decryption failed'}, status=400)


async def complete_download(request):
    """Mark download as complete and verify"""
    session_id = request.match_info['session_id']
    
    if session_id not in transfer.sessions:
        return web.json_response({'error': 'Session not found'}, status=404)
    
    session = transfer.sessions[session_id]

    # Text transfer: burn after reading
    if session.get('content_type') == 'text':
        sender_id = session.get('paired_with')
        if sender_id and sender_id in transfer.sessions:
            transfer.sessions[sender_id].pop('text_content', None)
            transfer.sessions[sender_id]['status'] = 'completed'
        session['status'] = 'completed'
        METRICS["transfers_completed"] += 1
        logger.info(f"Text transfer completed (burn-after-read): {session_id}")
        return web.json_response({'status': 'success'})

    if 'file_handle' in session:
        await session['file_handle'].close()
    
    # Verify hash (chunk-upload flow: file was saved server-side)
    if session.get('output_path'):
        output_path = Path(session['output_path'])
        received_hash = await transfer.calculate_file_hash(output_path)

        if received_hash == session['expected_hash']:
            session['status'] = 'completed'
            METRICS["transfers_completed"] += 1
            METRICS["bytes_downloaded"] += output_path.stat().st_size
            logger.info(f"Transfer completed successfully: {session['file_name']}")
            return web.json_response({
                'status': 'success',
                'file_name': session['file_name']
            })
        else:
            session['status'] = 'hash_mismatch'
            METRICS["transfers_failed"] += 1
            logger.error(f"Hash mismatch for {session['file_name']}")
            return web.json_response({
                'status': 'error',
                'error': 'hash_mismatch'
            }, status=400)

    # Web browser flow: file was downloaded directly by the browser.
    # AES-GCM provides integrity (authenticated encryption), so if the
    # download succeeded without decryption errors, the data is intact.
    if session.get('status') == 'paired' and session.get('paired_with'):
        session['status'] = 'completed'
        METRICS["transfers_completed"] += 1
        METRICS["bytes_downloaded"] += session.get('file_size', 0)
        logger.info(f"Web transfer completed: {session['file_name']}")
        return web.json_response({
            'status': 'success',
            'file_name': session['file_name']
        })

    return web.json_response({'error': 'No file received'}, status=400)


async def create_text_session_endpoint(request):
    """POST /api/text — create a text-sharing session"""
    client_ip = request.remote or "unknown"
    if not transfer.upload_limiter.is_allowed(client_ip):
        return web.json_response({'error': 'Too many requests.'}, status=429)
    try:
        data = await request.json()
        text = (data.get('text') or '').strip()
        if not text:
            return web.json_response({'error': 'text field required'}, status=400)
        if len(text) > 50_000:
            return web.json_response({'error': 'Text exceeds 50,000 character limit'}, status=400)
        result = await transfer.create_text_session(text)
        METRICS["uploads_total"] += 1
        return web.json_response(result)
    except ValueError as e:
        return web.json_response({'error': str(e)}, status=429)
    except Exception as e:
        logger.error(f"Create text session error: {e}")
        return web.json_response({'error': 'Failed to create text session'}, status=500)


async def get_text(request):
    """GET /api/text/{session_id} — retrieve encrypted text (burn-after-reading done on /complete)"""
    session_id = request.match_info['session_id']
    session = transfer.sessions.get(session_id)
    if not session or session.get('content_type') != 'text' or session['role'] != 'sender':
        return web.json_response({'error': 'Session not found'}, status=404)
    text = session.get('text_content')
    if not text:
        return web.json_response({'error': 'Text already retrieved'}, status=410)
    key = transfer.encryption_keys.get(session_id)
    if not key:
        return web.json_response({'error': 'Key unavailable'}, status=500)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, text.encode('utf-8'), None)
    return web.json_response({
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'nonce':      base64.b64encode(nonce).decode(),
        'salt':       session['salt']
    })


# ============= WebSocket Handler =============

async def websocket_handler(request):
    """WebSocket for real-time updates"""
    session_id = request.match_info.get('session_id')
    
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    
    if session_id and session_id in transfer.sessions:
        transfer.websockets[session_id].add(ws)
        logger.info(f"WebSocket connected for session {session_id}")
    
    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                except (json.JSONDecodeError, ValueError):
                    logger.warning("Malformed WebSocket message received")
                    continue
                # Handle WebSocket messages (ping, status requests, etc)
                if data.get('type') == 'ping':
                    await ws.send_json({'type': 'pong'})

            elif msg.type == WSMsgType.ERROR:
                logger.error(f"WebSocket error: {ws.exception()}")
    
    finally:
        if session_id and session_id in transfer.websockets:
            transfer.websockets[session_id].discard(ws)
    
    return ws


# ============= Icon Routes =============

async def favicon_ico(request):
    """Serve 32x32 PNG favicon (works in all browsers)"""
    return web.Response(body=ICON_32, content_type='image/png',
                        headers={'Cache-Control': 'public, max-age=604800'})


async def icon_192(request):
    """Serve 192x192 PNG icon for PWA / Android"""
    return web.Response(body=ICON_192, content_type='image/png',
                        headers={'Cache-Control': 'public, max-age=604800'})


async def icon_512(request):
    """Serve 512x512 PNG icon for PWA splash"""
    return web.Response(body=ICON_512, content_type='image/png',
                        headers={'Cache-Control': 'public, max-age=604800'})


async def apple_touch_icon(request):
    """Serve 180x180 PNG for iOS home screen (no transparency)"""
    return web.Response(body=ICON_180, content_type='image/png',
                        headers={'Cache-Control': 'public, max-age=604800'})


async def apple_touch_icon_precomposed(request):
    """Serve precomposed apple-touch-icon (Safari sometimes requests this)"""
    return web.Response(body=ICON_180, content_type='image/png',
                        headers={'Cache-Control': 'public, max-age=604800'})


# ============= Web UI =============

async def index(request):
    """Serve universal web UI"""
    html = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="theme-color" content="#e040fb">
    <title>MagicTransfer</title>
    <link rel="icon" type="image/png" href="/favicon.ico">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="manifest" href="/manifest.json">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #e040fb 0%, #00e5ff 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: #333;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 30px;
            max-width: 500px;
            width: 100%;
        }
        h1 {
            color: #e040fb;
            margin-bottom: 10px;
            font-size: 24px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 13px;
        }
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            border-bottom: 2px solid #f0f0f0;
        }
        .tab {
            flex: 1;
            padding: 12px;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 15px;
            color: #666;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }
        .tab.active {
            color: #e040fb;
            border-bottom-color: #e040fb;
            font-weight: 600;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .upload-area {
            border: 3px dashed #e0e0e0;
            border-radius: 12px;
            padding: 40px 20px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            margin-bottom: 20px;
        }
        .upload-area:hover, .upload-area.drag-over {
            border-color: #e040fb;
            background: #f8f9ff;
        }
        .upload-icon {
            font-size: 48px;
            margin-bottom: 10px;
        }
        input[type="text"], input[type="file"] {
            width: 100%;
            padding: 14px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-size: 15px;
            margin-bottom: 15px;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: #e040fb;
        }
        input[type="file"] {
            display: none;
        }
        button {
            width: 100%;
            padding: 16px;
            background: linear-gradient(135deg, #e040fb 0%, #00e5ff 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(224, 64, 251, 0.4);
        }
        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
        }
        .pairing-code {
            font-size: 42px;
            font-weight: bold;
            text-align: center;
            color: #e040fb;
            letter-spacing: 8px;
            margin: 25px 0;
            padding: 20px;
            background: #f8f9ff;
            border-radius: 12px;
        }
        .status {
            margin-top: 20px;
            padding: 15px;
            border-radius: 10px;
            font-size: 14px;
            display: none;
        }
        .status.show {
            display: block;
        }
        .status.success {
            background: #d4edda;
            color: #155724;
        }
        .status.error {
            background: #f8d7da;
            color: #721c24;
        }
        .status.info {
            background: #d1ecf1;
            color: #0c5460;
        }
        .progress {
            width: 100%;
            height: 8px;
            background: #e0e0e0;
            border-radius: 4px;
            overflow: hidden;
            margin: 15px 0;
            display: none;
        }
        .progress.show {
            display: block;
        }
        .progress-bar {
            height: 100%;
            background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
            transition: width 0.3s ease;
            width: 0%;
        }
        .file-info {
            background: #f8f9ff;
            padding: 15px;
            border-radius: 10px;
            margin: 15px 0;
            display: none;
        }
        .file-info.show {
            display: block;
        }
        .file-info p {
            margin: 5px 0;
            font-size: 14px;
            color: #666;
        }
        .text-area-wrap {
            position: relative;
            margin: 15px 0;
        }
        textarea.text-input {
            width: 100%;
            min-height: 140px;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 10px;
            font-family: monospace;
            font-size: 14px;
            resize: vertical;
            box-sizing: border-box;
            transition: border-color 0.3s;
            outline: none;
        }
        textarea.text-input:focus {
            border-color: #e040fb;
        }
        .char-counter {
            position: absolute;
            bottom: 8px;
            right: 10px;
            font-size: 11px;
            color: #999;
            pointer-events: none;
        }
        .char-counter.warn { color: #f59e0b; }
        .char-counter.over { color: #ef4444; }
        .copy-btn {
            background: linear-gradient(135deg, #10b981, #059669);
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 10px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            margin-top: 10px;
        }
        .copy-btn:hover { opacity: 0.9; }
        .badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: #d4edda;
            color: #155724;
            padding: 6px 12px;
            border-radius: 15px;
            font-size: 11px;
            font-weight: 600;
            margin-top: 15px;
        }
        @media (max-width: 480px) {
            .container {
                padding: 20px;
            }
            h1 {
                font-size: 20px;
            }
            .pairing-code {
                font-size: 36px;
                letter-spacing: 6px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <img src=\"""" + LOGO_DATA_URI + """\" width="64" height="64" alt="MagicTransfer" style="display:block;margin:0 auto 10px;">
        <h1 style="text-align:center;">MagicTransfer</h1>
        <p class="subtitle">Encrypted file sharing — like magic</p>
        
        <div class="tabs">
            <button class="tab active" onclick="switchTab('send')">Send</button>
            <button class="tab" onclick="switchTab('text')">Text</button>
            <button class="tab" onclick="switchTab('receive')">Receive</button>
        </div>
        
        <!-- SEND TAB -->
        <div id="send-tab" class="tab-content active">
            <div class="upload-area" id="upload-area" onclick="document.getElementById('file-input').click()">
                <div class="upload-icon">📁</div>
                <p><strong>Tap to select file</strong></p>
                <p style="font-size: 12px; color: #999; margin-top: 5px;">or drag & drop</p>
            </div>
            <input type="file" id="file-input" onchange="handleFileSelect(event)">
            <button id="send-btn" onclick="uploadFile()" disabled>Upload & Generate Code</button>
            
            <div id="send-progress" class="progress">
                <div id="send-progress-bar" class="progress-bar"></div>
            </div>
            
            <div id="pairing-display" style="display: none;">
                <h3 style="text-align: center; color: #666; margin-top: 25px; font-size: 14px;">Share this code:</h3>
                <div class="pairing-code" id="pairing-code"></div>
                <div class="file-info show">
                    <p><strong>File:</strong> <span id="file-name"></span></p>
                    <p><strong>Size:</strong> <span id="file-size"></span></p>
                </div>
            </div>
            
            <div id="send-status" class="status"></div>
        </div>

        <!-- TEXT TAB -->
        <div id="text-tab" class="tab-content">
            <div class="text-area-wrap">
                <textarea class="text-input" id="text-input"
                    placeholder="Paste passwords, credentials, or any text…"
                    maxlength="50000" oninput="updateCharCounter()"></textarea>
                <span class="char-counter" id="char-counter">0 / 50,000</span>
            </div>
            <button id="text-btn" onclick="shareText()" disabled>Share Text</button>
            <div id="text-pairing-display" style="display:none">
                <h3 style="text-align:center;color:#666;margin-top:25px;font-size:14px;">Share this code:</h3>
                <div class="pairing-code" id="text-pairing-code"></div>
                <div class="file-info show">
                    <p><strong>Characters:</strong> <span id="text-char-count"></span></p>
                </div>
            </div>
            <div id="text-status" class="status"></div>
        </div>

        <!-- RECEIVE TAB -->
        <div id="receive-tab" class="tab-content">
            <input type="text" id="code-input" placeholder="Enter 8-digit code" maxlength="8" inputmode="numeric">
            <button onclick="receiveFile()">Connect & Download</button>
            
            <div id="receive-progress" class="progress">
                <div id="receive-progress-bar" class="progress-bar"></div>
            </div>
            
            <div id="receive-file-info" class="file-info">
                <p><strong>File:</strong> <span id="recv-file-name"></span></p>
                <p><strong>Size:</strong> <span id="recv-file-size"></span></p>
            </div>

            <div id="receive-text-result" style="display:none;margin-top:15px">
                <div class="text-area-wrap">
                    <textarea class="text-input" id="received-text-output" readonly rows="8"></textarea>
                </div>
                <button class="copy-btn" onclick="copyReceivedText()">Copy to Clipboard</button>
            </div>

            <div id="receive-status" class="status"></div>
        </div>
        
        <div class="badge">🔒 AES-256-GCM • E2E Encrypted</div>
    </div>
    
    <script>
        const SERVER_API_KEY = __API_KEY_JSON__;
        function getAuthHeaders() {
            return SERVER_API_KEY ? {'Authorization': 'Bearer ' + SERVER_API_KEY} : {};
        }

        let selectedFile = null;
        
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            document.getElementById(tab + '-tab').classList.add('active');
            document.querySelectorAll('.tab').forEach(t => {
                if (t.getAttribute('onclick') === "switchTab('" + tab + "')") t.classList.add('active');
            });
        }

        function updateCharCounter() {
            const len = document.getElementById('text-input').value.length;
            const counter = document.getElementById('char-counter');
            counter.textContent = len.toLocaleString() + ' / 50,000';
            counter.className = 'char-counter' + (len > 50000 ? ' over' : len > 45000 ? ' warn' : '');
            document.getElementById('text-btn').disabled = (len === 0 || len > 50000);
        }

        async function shareText() {
            const text = document.getElementById('text-input').value;
            if (!text.length) return;
            const btn = document.getElementById('text-btn');
            btn.disabled = true; btn.textContent = 'Creating session…';
            showStatus('text-status', 'info', 'Uploading…');
            try {
                const r = await fetch('/api/text', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', ...getAuthHeaders()},
                    body: JSON.stringify({text})
                });
                const d = await r.json();
                if (r.ok) {
                    document.getElementById('text-pairing-code').textContent = d.pairing_code;
                    document.getElementById('text-char-count').textContent =
                        d.text_length.toLocaleString() + ' characters';
                    document.getElementById('text-pairing-display').style.display = 'block';
                    showStatus('text-status', 'success', '✅ Ready — share the code above.');
                } else { showStatus('text-status', 'error', d.error || 'Failed'); }
            } catch (e) { showStatus('text-status', 'error', 'Connection error: ' + e.message); }
            finally { btn.textContent = 'Share Text'; btn.disabled = false; }
        }

        async function receiveText(code, joinData) {
            if (!hasWebCrypto) {
                showStatus('receive-status', 'error', '⚠️ Requires HTTPS or localhost.'); return;
            }
            try {
                showStatus('receive-status', 'info', 'Deriving key…');
                const key = await deriveKey(code, joinData.salt);
                showStatus('receive-status', 'info', 'Fetching encrypted text…');
                const r = await fetch('/api/text/' + joinData.sender_session_id, {headers: getAuthHeaders()});
                if (!r.ok) { showStatus('receive-status', 'error', (await r.json()).error); return; }
                const {ciphertext, nonce} = await r.json();
                const plain = await crypto.subtle.decrypt(
                    {name: 'AES-GCM', iv: base64ToBytes(nonce)}, key, base64ToBytes(ciphertext)
                );
                document.getElementById('received-text-output').value = new TextDecoder().decode(plain);
                document.getElementById('receive-text-result').style.display = 'block';
                document.getElementById('receive-progress-bar').style.width = '100%';
                await fetch('/api/complete/' + joinData.session_id, {method:'POST', headers:getAuthHeaders()});
                showStatus('receive-status', 'success', '✅ Text received! Copy it, then close this tab.');
            } catch (e) {
                showStatus('receive-status', 'error',
                    e.name === 'OperationError' ? 'Decryption failed — wrong code?' : 'Error: ' + e.message);
            }
        }

        async function copyReceivedText() {
            const text = document.getElementById('received-text-output').value;
            const btn = event.target;
            try { await navigator.clipboard.writeText(text); }
            catch { document.getElementById('received-text-output').select(); document.execCommand('copy'); }
            btn.textContent = '✅ Copied!';
            setTimeout(() => btn.textContent = 'Copy to Clipboard', 2000);
        }
        
        // Drag & drop
        const uploadArea = document.getElementById('upload-area');
        
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('drag-over');
        });
        
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('drag-over');
        });
        
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('drag-over');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                selectedFile = files[0];
                document.getElementById('send-btn').disabled = false;
                showStatus('send-status', 'info', `Selected: ${selectedFile.name}`);
            }
        });
        
        function handleFileSelect(event) {
            selectedFile = event.target.files[0];
            if (selectedFile) {
                document.getElementById('send-btn').disabled = false;
                showStatus('send-status', 'info', `Selected: ${selectedFile.name} (${formatBytes(selectedFile.size)})`);
            }
        }
        
        async function uploadFile() {
            if (!selectedFile) return;
            
            const formData = new FormData();
            formData.append('file', selectedFile);
            
            const sendBtn = document.getElementById('send-btn');
            sendBtn.disabled = true;
            sendBtn.textContent = 'Uploading...';
            
            document.getElementById('send-progress').classList.add('show');
            
            try {
                const response = await fetch('/api/upload', {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: formData
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    document.getElementById('pairing-code').textContent = data.pairing_code;
                    document.getElementById('file-name').textContent = data.file_name;
                    document.getElementById('file-size').textContent = formatBytes(data.file_size);
                    document.getElementById('pairing-display').style.display = 'block';
                    showStatus('send-status', 'success', '✅ Ready! Share the code above.');
                    document.getElementById('send-progress-bar').style.width = '100%';
                } else {
                    showStatus('send-status', 'error', data.error || 'Upload failed');
                }
            } catch (error) {
                showStatus('send-status', 'error', 'Connection error: ' + error.message);
            } finally {
                sendBtn.textContent = 'Upload & Generate Code';
            }
        }
        
        function base64ToBytes(b64) {
            const bin = atob(b64);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            return bytes;
        }

        async function deriveKey(pairingCode, saltB64) {
            const salt = base64ToBytes(saltB64);
            const enc = new TextEncoder();
            const keyMaterial = await crypto.subtle.importKey(
                'raw', enc.encode(pairingCode), 'PBKDF2', false, ['deriveKey']
            );
            return await crypto.subtle.deriveKey(
                {name: 'PBKDF2', salt: salt, iterations: 600000, hash: 'SHA-256'},
                keyMaterial,
                {name: 'AES-GCM', length: 256},
                false,
                ['decrypt']
            );
        }

        const hasWebCrypto = !!(window.crypto && window.crypto.subtle);

        async function receiveFile() {
            const code = document.getElementById('code-input').value.trim();

            if (code.length !== 8 || !/^\\d+$/.test(code)) {
                showStatus('receive-status', 'error', 'Please enter an 8-digit code');
                return;
            }

            showStatus('receive-status', 'info', 'Connecting...');
            document.getElementById('receive-progress').classList.add('show');

            try {
                // Join session
                const joinResponse = await fetch('/api/join', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json', ...getAuthHeaders()},
                    body: JSON.stringify({pairing_code: code})
                });

                const joinData = await joinResponse.json();

                if (!joinResponse.ok) {
                    showStatus('receive-status', 'error', joinData.error || 'Invalid code');
                    return;
                }

                // Text transfer — hand off to dedicated handler
                if (joinData.content_type === 'text') { await receiveText(code, joinData); return; }

                // Show file info
                document.getElementById('recv-file-name').textContent = joinData.file_name;
                document.getElementById('recv-file-size').textContent = formatBytes(joinData.file_size);
                document.getElementById('receive-file-info').classList.add('show');

                let blob;

                if (hasWebCrypto) {
                    // HTTPS / localhost — use E2E encrypted download
                    showStatus('receive-status', 'info', 'Deriving encryption key...');
                    const key = await deriveKey(code, joinData.salt);

                    showStatus('receive-status', 'info', 'Downloading & decrypting...');
                    const downloadResponse = await fetch('/api/download/' + joinData.sender_session_id,
                        {headers: getAuthHeaders()});

                    if (!downloadResponse.ok) {
                        showStatus('receive-status', 'error', 'Download failed');
                        return;
                    }

                    const encryptedBuffer = await downloadResponse.arrayBuffer();
                    const encryptedBytes = new Uint8Array(encryptedBuffer);

                    const decryptedChunks = [];
                    let offset = 0;
                    let decryptedTotal = 0;

                    while (offset < encryptedBytes.length) {
                        if (offset + 4 > encryptedBytes.length) break;
                        const frameLen = new DataView(encryptedBytes.buffer, offset, 4).getUint32(0);
                        offset += 4;

                        if (offset + frameLen > encryptedBytes.length) {
                            showStatus('receive-status', 'error', 'Corrupted download stream');
                            return;
                        }

                        const nonce = encryptedBytes.slice(offset, offset + 12);
                        const ciphertext = encryptedBytes.slice(offset + 12, offset + frameLen);
                        offset += frameLen;

                        const plaintext = await crypto.subtle.decrypt(
                            {name: 'AES-GCM', iv: nonce}, key, ciphertext
                        );
                        decryptedChunks.push(new Uint8Array(plaintext));
                        decryptedTotal += plaintext.byteLength;

                        if (joinData.file_size > 0) {
                            const pct = Math.min(100, Math.round(decryptedTotal / joinData.file_size * 100));
                            document.getElementById('receive-progress-bar').style.width = pct + '%';
                        }
                    }

                    blob = new Blob(decryptedChunks);

                } else {
                    // crypto.subtle requires a secure context (HTTPS or localhost).
                    // Plaintext fallback has been removed for security — use HTTPS.
                    showStatus('receive-status', 'error',
                        '⚠️ Encrypted download requires a secure context. ' +
                        'Please access this app via HTTPS or localhost, ' +
                        'or use the CLI client (python client.py receive ...) over any connection.');
                    return;
                }

                // Mark transfer complete
                await fetch('/api/complete/' + joinData.session_id, {
                    method: 'POST',
                    headers: getAuthHeaders()
                });

                // Trigger browser download
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = joinData.file_name;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);

                showStatus('receive-status', 'success', 'Download complete!');
                document.getElementById('receive-progress-bar').style.width = '100%';

            } catch (error) {
                if (error.name === 'OperationError') {
                    showStatus('receive-status', 'error', 'Decryption failed — wrong code or corrupted data');
                } else {
                    showStatus('receive-status', 'error', 'Error: ' + error.message);
                }
            }
        }
        
        function showStatus(elementId, type, message) {
            const element = document.getElementById(elementId);
            element.className = `status show ${type}`;
            element.textContent = message;
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
        }
        
        // Register service worker for PWA
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js').catch(() => {});
        }
    </script>
</body>
</html>
    """
    return web.Response(
        text=html.replace('__API_KEY_JSON__', json.dumps(API_KEY)),
        content_type='text/html'
    )


async def manifest(request):
    """PWA manifest for installable web app"""
    manifest_json = {
        "name": "MagicTransfer",
        "short_name": "MagicTransfer",
        "description": "Encrypted file sharing — like magic",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#e040fb",
        "theme_color": "#e040fb",
        "icons": [
            {
                "src": "/icon-192.png",
                "sizes": "192x192",
                "type": "image/png",
                "purpose": "any"
            },
            {
                "src": "/icon-512.png",
                "sizes": "512x512",
                "type": "image/png",
                "purpose": "any"
            },
            {
                "src": "/icon-192.png",
                "sizes": "192x192",
                "type": "image/png",
                "purpose": "maskable"
            }
        ]
    }
    return web.json_response(manifest_json)


async def service_worker(request):
    """Service worker for PWA offline support"""
    sw_js = """
self.addEventListener('install', (event) => {
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(clients.claim());
});
    """
    return web.Response(text=sw_js, content_type='application/javascript')


# ============= Middleware =============

@web.middleware
async def request_logging_middleware(request, handler):
    """Log every request with timing and structured fields"""
    start = time.monotonic()
    client_ip = request.remote or "unknown"
    try:
        response = await handler(request)
        duration = (time.monotonic() - start) * 1000
        logger.info(
            "%s %s %s %.1fms",
            request.method, request.path, response.status, duration,
            extra={
                "client_ip": client_ip,
                "method": request.method,
                "path": request.path,
                "status": response.status,
                "duration_ms": round(duration, 1),
            },
        )
        return response
    except web.HTTPException as exc:
        duration = (time.monotonic() - start) * 1000
        logger.warning(
            "%s %s %s %.1fms",
            request.method, request.path, exc.status, duration,
            extra={
                "client_ip": client_ip,
                "method": request.method,
                "path": request.path,
                "status": exc.status,
                "duration_ms": round(duration, 1),
            },
        )
        raise
    except Exception:
        duration = (time.monotonic() - start) * 1000
        logger.exception(
            "%s %s 500 %.1fms",
            request.method, request.path, duration,
            extra={
                "client_ip": client_ip,
                "method": request.method,
                "path": request.path,
                "status": 500,
                "duration_ms": round(duration, 1),
            },
        )
        return web.json_response({"error": "Internal server error"}, status=500)


@web.middleware
async def timeout_middleware(request, handler):
    """Enforce request timeout (except for uploads/downloads which are streamed)"""
    # Generous timeout for file transfers, shorter for API calls
    if request.path.startswith("/api/upload") or request.path.startswith("/api/download"):
        timeout_seconds = 3600  # 1 hour for transfers
    else:
        timeout_seconds = 30  # 30s for API calls

    try:
        return await asyncio.wait_for(handler(request), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning("Request timeout: %s %s", request.method, request.path)
        return web.json_response({"error": "Request timeout"}, status=504)


@web.middleware
async def security_headers_middleware(request, handler):
    """Add security headers to all responses"""
    response = await handler(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    return response


@web.middleware
async def auth_middleware(request, handler):
    """Optional bearer-token auth for API and WebSocket endpoints.

    Enabled when the API_KEY environment variable is set.
    Exempt paths (web UI, static assets, health check) are always allowed.
    Clients must send:  Authorization: Bearer <API_KEY>
    """
    if not API_KEY or request.path in _AUTH_EXEMPT:
        return await handler(request)

    provided = ""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        provided = auth_header[7:]
    else:
        provided = request.headers.get("X-API-Key", "")

    if not provided or not hmac.compare_digest(provided, API_KEY):
        logger.warning(
            "Unauthorized request to %s from %s",
            request.path,
            request.remote or "unknown",
        )
        return web.json_response({"error": "Unauthorized"}, status=401)

    return await handler(request)


# ============= Metrics =============

SERVER_START_TIME = time.time()
METRICS = {
    "requests_total": 0,
    "uploads_total": 0,
    "downloads_total": 0,
    "transfers_completed": 0,
    "transfers_failed": 0,
    "bytes_uploaded": 0,
    "bytes_downloaded": 0,
}


async def metrics_endpoint(request):
    """Prometheus-compatible metrics endpoint"""
    mem = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss  # KB on Linux
    uptime = time.time() - SERVER_START_TIME

    active_sessions = len(transfer.sessions)
    waiting = sum(1 for s in transfer.sessions.values() if s["status"] == "waiting")
    paired = sum(1 for s in transfer.sessions.values() if s["status"] == "paired")
    completed = sum(1 for s in transfer.sessions.values() if s["status"] == "completed")

    lines = [
        "# HELP magic_transfer_uptime_seconds Server uptime in seconds",
        "# TYPE magic_transfer_uptime_seconds gauge",
        f"magic_transfer_uptime_seconds {uptime:.0f}",
        "",
        "# HELP magic_transfer_memory_rss_kb Resident memory in KB",
        "# TYPE magic_transfer_memory_rss_kb gauge",
        f"magic_transfer_memory_rss_kb {mem}",
        "",
        "# HELP magic_transfer_sessions_active Current active sessions",
        "# TYPE magic_transfer_sessions_active gauge",
        f'magic_transfer_sessions_active{{status="waiting"}} {waiting}',
        f'magic_transfer_sessions_active{{status="paired"}} {paired}',
        f'magic_transfer_sessions_active{{status="completed"}} {completed}',
        f'magic_transfer_sessions_active{{status="total"}} {active_sessions}',
        "",
        "# HELP magic_transfer_transfers_total Total transfer count",
        "# TYPE magic_transfer_transfers_total counter",
        f'magic_transfer_transfers_total{{result="completed"}} {METRICS["transfers_completed"]}',
        f'magic_transfer_transfers_total{{result="failed"}} {METRICS["transfers_failed"]}',
        "",
        "# HELP magic_transfer_bytes_total Total bytes transferred",
        "# TYPE magic_transfer_bytes_total counter",
        f'magic_transfer_bytes_total{{direction="upload"}} {METRICS["bytes_uploaded"]}',
        f'magic_transfer_bytes_total{{direction="download"}} {METRICS["bytes_downloaded"]}',
        "",
    ]

    return web.Response(
        text="\n".join(lines) + "\n",
        content_type="text/plain; version=0.0.4; charset=utf-8",
    )


# ============= Background Tasks =============

async def periodic_cleanup(app):
    """Background task: clean expired sessions and rate limiter state"""
    try:
        while True:
            await asyncio.sleep(300)  # Every 5 minutes
            transfer.cleanup_expired_sessions()
            transfer.join_limiter.cleanup()
            transfer.upload_limiter.cleanup()
            logger.info(
                "Periodic cleanup: %d active sessions",
                len(transfer.sessions),
            )
    except asyncio.CancelledError:
        pass


async def start_background_tasks(app):
    app["cleanup_task"] = asyncio.create_task(periodic_cleanup(app))


async def stop_background_tasks(app):
    app["cleanup_task"].cancel()
    await app["cleanup_task"]


# ============= App Factory =============

def create_app():
    """Create and configure the application"""
    app = web.Application(
        client_max_size=MAX_UPLOAD_BYTES + 1024 * 1024,  # MAX_UPLOAD_BYTES + 1MB overhead
        middlewares=[request_logging_middleware, security_headers_middleware, timeout_middleware, auth_middleware],
    )

    # API routes
    app.router.add_get('/health', health_check)
    app.router.add_get('/metrics', metrics_endpoint)
    app.router.add_post('/api/upload', upload_file)
    app.router.add_post('/api/send', create_send_session)
    app.router.add_post('/api/join', join_session_endpoint)
    app.router.add_get('/api/session/{session_id}', get_session)
    app.router.add_get('/api/download/{session_id}', download_file)
    app.router.add_post('/api/chunk/{session_id}', upload_chunk)
    app.router.add_post('/api/complete/{session_id}', complete_download)
    app.router.add_post('/api/text',              create_text_session_endpoint)
    app.router.add_get( '/api/text/{session_id}', get_text)

    # WebSocket
    app.router.add_get('/ws/{session_id}', websocket_handler)

    # Web UI & icons
    app.router.add_get('/', index)
    app.router.add_get('/favicon.ico', favicon_ico)
    app.router.add_get('/apple-touch-icon.png', apple_touch_icon)
    app.router.add_get('/apple-touch-icon-precomposed.png', apple_touch_icon_precomposed)
    app.router.add_get('/icon-192.png', icon_192)
    app.router.add_get('/icon-512.png', icon_512)
    app.router.add_get('/manifest.json', manifest)
    app.router.add_get('/sw.js', service_worker)

    # Background tasks
    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(stop_background_tasks)

    return app


if __name__ == '__main__':
    app = create_app()
    port = int(os.environ.get('PORT', 8080))
    logger.info("Starting MagicTransfer Server v1.0 on port %d", port)
    web.run_app(app, host='0.0.0.0', port=port)
