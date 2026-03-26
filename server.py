#!/usr/bin/env python3
"""
MagicTransfer Server — Zero-Knowledge Encrypted File & Text Sharing

Architecture: Firefox Send model
- All encryption/decryption happens in the browser (Web Crypto API)
- Server stores only encrypted blobs — never sees plaintext or keys
- Share URLs contain the decryption key in the URL fragment (#), which
  is never sent to the server per RFC 3986
- Auth tokens derived from the key via HKDF prove download authorization
  without revealing the key
"""

import asyncio
import json
import re
import secrets
import hmac
import base64
import os
import time
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import logging

from io import BytesIO
from aiohttp import web
import aiofiles
from PIL import Image, ImageDraw


# ============= Configuration =============

MAX_UPLOAD_BYTES = int(os.environ.get("MAX_UPLOAD_BYTES", str(500 * 1024 * 1024)))
MAX_TEXT_BYTES = int(os.environ.get("MAX_TEXT_BYTES", str(200 * 1024)))  # 200KB encrypted text
MAX_META_BYTES = 8192
SESSION_TTL_MINUTES = int(os.environ.get("SESSION_TTL_MINUTES", "60"))
MAX_SESSIONS = int(os.environ.get("MAX_SESSIONS", "200"))


# ============= Structured Logging =============

class JSONFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        for key in ("client_ip", "method", "path", "status", "duration_ms"):
            if hasattr(record, key):
                entry[key] = getattr(record, key)
        return json.dumps(entry)


def setup_logging():
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
            "%(asctime)s %(levelname)-8s %(name)s  %(message)s"))
    root.addHandler(handler)


setup_logging()
logger = logging.getLogger("magic-transfer")


# ============= Rate Limiter =============

class RateLimiter:
    def __init__(self, max_attempts: int, window_seconds: int):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: Dict[str, list] = {}

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        if key not in self._attempts:
            self._attempts[key] = []
        self._attempts[key] = [
            t for t in self._attempts[key]
            if now - t < self.window_seconds
        ]
        if len(self._attempts[key]) >= self.max_attempts:
            return False
        self._attempts[key].append(now)
        return True

    def cleanup(self):
        now = time.time()
        stale = [k for k, v in self._attempts.items()
                 if not v or now - v[-1] > self.window_seconds]
        for k in stale:
            del self._attempts[k]


# ============= Blob Store =============

class BlobStore:
    """Zero-knowledge encrypted blob store. Never sees plaintext or keys."""

    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.upload_dir = Path("/output/uploads")
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        self.upload_limiter = RateLimiter(max_attempts=10, window_seconds=60)
        self.download_limiter = RateLimiter(max_attempts=30, window_seconds=60)

    def create_file_session(self, file_id: str, auth_token: str,
                            encrypted_meta: str, file_path: Path,
                            blob_size: int) -> Dict[str, Any]:
        session = {
            'file_id': file_id,
            'auth_token': auth_token,
            'encrypted_meta': encrypted_meta,
            'file_path': str(file_path),
            'content_type': 'file',
            'blob_size': blob_size,
            'status': 'active',
            'created_at': datetime.now().isoformat(),
        }
        self.sessions[file_id] = session
        return session

    def create_text_session(self, file_id: str, auth_token: str,
                            encrypted_meta: str, encrypted_text: str) -> Dict[str, Any]:
        session = {
            'file_id': file_id,
            'auth_token': auth_token,
            'encrypted_meta': encrypted_meta,
            'encrypted_text': encrypted_text,
            'content_type': 'text',
            'blob_size': len(encrypted_text),
            'status': 'active',
            'created_at': datetime.now().isoformat(),
        }
        self.sessions[file_id] = session
        return session

    def get_session(self, file_id: str) -> Optional[Dict[str, Any]]:
        return self.sessions.get(file_id)

    def verify_auth(self, file_id: str, provided_token: str) -> bool:
        session = self.sessions.get(file_id)
        if not session:
            return False
        return hmac.compare_digest(session['auth_token'], provided_token)

    def mark_downloaded(self, file_id: str):
        session = self.sessions.get(file_id)
        if session:
            session['status'] = 'downloaded'

    def delete_session(self, file_id: str):
        session = self.sessions.pop(file_id, None)
        if session and session.get('file_path'):
            try:
                Path(session['file_path']).unlink(missing_ok=True)
            except OSError as e:
                logger.error(f"Failed to delete blob {file_id}: {e}")

    def cleanup_expired(self):
        now = datetime.now()
        ttl = timedelta(minutes=SESSION_TTL_MINUTES)
        expired = [
            fid for fid, s in self.sessions.items()
            if now - datetime.fromisoformat(s['created_at']) > ttl
        ]
        for fid in expired:
            logger.info(f"Expiring session {fid}")
            self.delete_session(fid)

        # Orphan file cleanup
        try:
            known_paths = {
                s.get('file_path') for s in self.sessions.values()
                if s.get('file_path')
            }
            for f in self.upload_dir.iterdir():
                if f.is_file() and str(f) not in known_paths:
                    age = time.time() - f.stat().st_mtime
                    if age > SESSION_TTL_MINUTES * 60:
                        f.unlink(missing_ok=True)
                        logger.info(f"Deleted orphan file: {f.name}")
        except OSError:
            pass


store = BlobStore()


# ============= Metrics =============

METRICS = {
    "uploads_total": 0,
    "downloads_total": 0,
    "text_shares_total": 0,
    "bytes_uploaded": 0,
    "bytes_downloaded": 0,
    "active_sessions": 0,
}


# ============= Icon Generation =============

def _lerp_color(c1, c2, t):
    return tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))


def generate_icon_png(size):
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx, cy = size // 2, size // 2
    r = size // 2 - 1
    c_start = (224, 64, 251)   # #e040fb magenta
    c_end = (0, 229, 255)      # #00e5ff cyan
    for y in range(size):
        for x in range(size):
            dx, dy = x - cx, y - cy
            if dx * dx + dy * dy <= r * r:
                t = (x + y) / (2 * size)
                img.putpixel((x, y), _lerp_color(c_start, c_end, t) + (255,))
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


def generate_apple_icon_png(size):
    img = Image.new('RGB', (size, size), (224, 64, 251))
    draw = ImageDraw.Draw(img)
    c_start = (224, 64, 251)
    c_end = (0, 229, 255)
    for y in range(size):
        for x in range(size):
            t = (x + y) / (2 * size)
            img.putpixel((x, y), _lerp_color(c_start, c_end, t))
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


ICON_32 = generate_icon_png(32)
ICON_180 = generate_apple_icon_png(180)
ICON_192 = generate_apple_icon_png(192)
ICON_512 = generate_apple_icon_png(512)

_logo_b64 = base64.b64encode(ICON_192).decode()
LOGO_DATA_URI = f'data:image/png;base64,{_logo_b64}'


# ============= Helper: Extract auth token =============

def _get_client_ip(request) -> str:
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip.strip()
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote or "unknown"


def _get_auth_token(request) -> str:
    return request.headers.get('Authorization', '').removeprefix('Bearer ').strip()


# ============= API Endpoints =============

async def health_check(request):
    return web.json_response({'status': 'ok', 'version': '3.0'})


async def upload_file(request):
    """Receive pre-encrypted file blob + encrypted metadata + auth token."""
    client_ip = _get_client_ip(request)
    if not store.upload_limiter.is_allowed(client_ip):
        return web.json_response({'error': 'Too many uploads. Try again later.'}, status=429)

    if len(store.sessions) >= MAX_SESSIONS:
        return web.json_response({'error': 'Server busy. Try again later.'}, status=429)

    try:
        reader = await request.multipart()
        file_id = secrets.token_urlsafe(16)
        file_path = store.upload_dir / f"{file_id}.bin"
        auth_token = None
        encrypted_meta = None
        total_bytes = 0

        async for part in reader:
            if part.name == 'blob':
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
            elif part.name == 'meta':
                encrypted_meta = (await part.read()).decode('utf-8')
            elif part.name == 'auth_token':
                auth_token = (await part.read()).decode('utf-8')

        if not auth_token or not encrypted_meta or total_bytes == 0:
            file_path.unlink(missing_ok=True)
            return web.json_response({'error': 'Missing required fields: blob, meta, auth_token'}, status=400)

        if len(encrypted_meta) > MAX_META_BYTES:
            file_path.unlink(missing_ok=True)
            return web.json_response({'error': 'Metadata too large'}, status=413)

        if len(auth_token) != 64:  # 32 bytes = 64 hex chars
            file_path.unlink(missing_ok=True)
            return web.json_response({'error': 'Invalid auth token'}, status=400)

        store.create_file_session(file_id, auth_token, encrypted_meta, file_path, total_bytes)
        METRICS["uploads_total"] += 1
        METRICS["bytes_uploaded"] += total_bytes
        logger.info(f"Upload: {file_id} ({total_bytes} bytes) from {client_ip}")

        return web.json_response({'file_id': file_id})

    except Exception as e:
        logger.error(f"Upload error: {type(e).__name__}: {e}")
        if 'file_path' in locals():
            file_path.unlink(missing_ok=True)
        return web.json_response({'error': 'Upload failed'}, status=500)


async def create_text(request):
    """Store pre-encrypted text blob + encrypted metadata + auth token."""
    client_ip = _get_client_ip(request)
    if not store.upload_limiter.is_allowed(client_ip):
        return web.json_response({'error': 'Too many requests.'}, status=429)

    if len(store.sessions) >= MAX_SESSIONS:
        return web.json_response({'error': 'Server busy. Try again later.'}, status=429)

    try:
        data = await request.json()
        encrypted_text = data.get('encrypted_text', '')
        encrypted_meta = data.get('meta', '')
        auth_token = data.get('auth_token', '')

        if not encrypted_text or not encrypted_meta or not auth_token:
            return web.json_response({'error': 'Missing required fields'}, status=400)

        if len(encrypted_meta) > MAX_META_BYTES:
            return web.json_response({'error': 'Metadata too large'}, status=413)

        if len(auth_token) != 64:
            return web.json_response({'error': 'Invalid auth token'}, status=400)

        if len(encrypted_text) > MAX_TEXT_BYTES:
            return web.json_response({'error': 'Text too large'}, status=413)

        file_id = secrets.token_urlsafe(16)
        store.create_text_session(file_id, auth_token, encrypted_meta, encrypted_text)
        METRICS["text_shares_total"] += 1
        logger.info(f"Text share: {file_id} from {client_ip}")

        return web.json_response({'file_id': file_id})

    except Exception as e:
        logger.error(f"Text share error: {type(e).__name__}: {e}")
        return web.json_response({'error': 'Failed to create text share'}, status=500)


async def get_info(request):
    """Return content type + encrypted metadata for a session (requires auth)."""
    file_id = request.match_info['file_id']
    if not re.fullmatch(r'[A-Za-z0-9_-]{16,32}', file_id):
        return web.json_response({'error': 'Invalid file ID'}, status=400)
    token = _get_auth_token(request)

    if not store.verify_auth(file_id, token):
        return web.json_response({'error': 'Unauthorized'}, status=401)

    session = store.get_session(file_id)
    if not session or session['status'] == 'expired':
        return web.json_response({'error': 'Not found or expired'}, status=404)

    return web.json_response({
        'content_type': session['content_type'],
        'encrypted_meta': session['encrypted_meta'],
        'blob_size': session['blob_size'],
        'status': session['status'],
    })


async def download_file(request):
    """Stream encrypted blob back to the browser (requires auth)."""
    file_id = request.match_info['file_id']
    if not re.fullmatch(r'[A-Za-z0-9_-]{16,32}', file_id):
        return web.json_response({'error': 'Invalid file ID'}, status=400)
    client_ip = _get_client_ip(request)

    if not store.download_limiter.is_allowed(client_ip):
        return web.json_response({'error': 'Too many requests.'}, status=429)

    token = _get_auth_token(request)
    if not store.verify_auth(file_id, token):
        return web.json_response({'error': 'Unauthorized'}, status=401)

    session = store.get_session(file_id)
    if not session or session['content_type'] != 'file':
        return web.json_response({'error': 'Not found'}, status=404)

    if session['status'] in ('downloaded', 'downloading'):
        return web.json_response({'error': 'Already downloaded'}, status=410)

    # Atomically mark as downloading to prevent race condition
    session['status'] = 'downloading'

    file_path = Path(session['file_path'])
    if not file_path.exists():
        return web.json_response({'error': 'File not found'}, status=404)

    response = web.StreamResponse()
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['Content-Length'] = str(session['blob_size'])
    response.headers['Cache-Control'] = 'no-store'
    await response.prepare(request)

    async with aiofiles.open(file_path, 'rb') as f:
        while chunk := await f.read(65536):
            await response.write(chunk)

    await response.write_eof()

    METRICS["downloads_total"] += 1
    METRICS["bytes_downloaded"] += session['blob_size']
    logger.info(f"Download: {file_id} to {client_ip}")

    return response


async def get_text(request):
    """Return encrypted text blob (requires auth)."""
    file_id = request.match_info['file_id']
    if not re.fullmatch(r'[A-Za-z0-9_-]{16,32}', file_id):
        return web.json_response({'error': 'Invalid file ID'}, status=400)
    client_ip = _get_client_ip(request)

    if not store.download_limiter.is_allowed(client_ip):
        return web.json_response({'error': 'Too many requests.'}, status=429)

    token = _get_auth_token(request)
    if not store.verify_auth(file_id, token):
        return web.json_response({'error': 'Unauthorized'}, status=401)

    session = store.get_session(file_id)
    if not session or session['content_type'] != 'text':
        return web.json_response({'error': 'Not found'}, status=404)

    if session['status'] in ('downloaded', 'downloading'):
        return web.json_response({'error': 'Already retrieved'}, status=410)

    # Atomically mark as downloading to prevent race condition
    session['status'] = 'downloading'

    METRICS["downloads_total"] += 1
    logger.info(f"Text retrieve: {file_id} to {client_ip}")

    return web.json_response({
        'encrypted_text': session['encrypted_text'],
        'encrypted_meta': session['encrypted_meta'],
    })


async def complete_transfer(request):
    """Burn-after-read: delete the blob/text after successful download."""
    file_id = request.match_info['file_id']
    if not re.fullmatch(r'[A-Za-z0-9_-]{16,32}', file_id):
        return web.json_response({'error': 'Invalid file ID'}, status=400)
    token = _get_auth_token(request)

    if not store.verify_auth(file_id, token):
        return web.json_response({'error': 'Unauthorized'}, status=401)

    session = store.get_session(file_id)
    if not session:
        return web.json_response({'error': 'Not found'}, status=404)

    store.mark_downloaded(file_id)
    store.delete_session(file_id)
    logger.info(f"Burned: {file_id}")

    return web.json_response({'status': 'deleted'})


# ============= Icon Routes =============

async def favicon_ico(request):
    return web.Response(body=ICON_32, content_type='image/png',
                        headers={'Cache-Control': 'public, max-age=604800'})


async def icon_192(request):
    return web.Response(body=ICON_192, content_type='image/png',
                        headers={'Cache-Control': 'public, max-age=604800'})


async def icon_512(request):
    return web.Response(body=ICON_512, content_type='image/png',
                        headers={'Cache-Control': 'public, max-age=604800'})


async def apple_touch_icon(request):
    return web.Response(body=ICON_180, content_type='image/png',
                        headers={'Cache-Control': 'public, max-age=604800'})


async def manifest_json(request):
    return web.json_response({
        "name": "MagicTransfer",
        "short_name": "MagicTransfer",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#e040fb",
        "theme_color": "#e040fb",
        "icons": [
            {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
            {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png"}
        ]
    }, headers={'Cache-Control': 'public, max-age=604800'})


# ============= Metrics Endpoint =============

METRICS_TOKEN = os.environ.get("METRICS_TOKEN", "")


async def metrics(request):
    if not METRICS_TOKEN:
        return web.json_response({'error': 'Metrics disabled'}, status=403)
    provided = _get_auth_token(request)
    if not hmac.compare_digest(METRICS_TOKEN, provided):
        return web.json_response({'error': 'Unauthorized'}, status=401)
    METRICS["active_sessions"] = len(store.sessions)
    lines = []
    for k, v in METRICS.items():
        lines.append(f"magictransfer_{k} {v}")
    return web.Response(text="\n".join(lines) + "\n",
                        content_type="text/plain; version=0.0.4")


# ============= Web UI: Shared JS Crypto Module =============

CRYPTO_JS = """
// ============= Zero-Knowledge Crypto Module =============
// All encryption/decryption happens here in the browser.
// The server never sees plaintext, keys, or filenames.

const CHUNK_SIZE = 65536; // 64KB

function base64urlEncode(buf) {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function bufToHex(buf) {
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function generateIKM() {
    return crypto.getRandomValues(new Uint8Array(32));
}

async function deriveKeys(ikm) {
    const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits', 'deriveKey']);
    // Use a fixed domain-separation salt (not secret, but avoids all-zeros)
    const salt = new TextEncoder().encode('MagicTransfer-v3-HKDF-salt-2026');
    const enc = new TextEncoder();

    const fileKey = await crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: salt, info: enc.encode('file') },
        baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
    const metaKey = await crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: salt, info: enc.encode('meta') },
        baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
    const authBits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: salt, info: enc.encode('auth') },
        baseKey, 256
    );
    const authToken = bufToHex(authBits);

    return { fileKey, metaKey, authToken };
}

async function encryptMeta(metaKey, metadata) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(JSON.stringify(metadata));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, metaKey, encoded);
    const combined = new Uint8Array(12 + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), 12);
    return base64urlEncode(combined);
}

async function decryptMeta(metaKey, encryptedMetaB64) {
    const data = base64urlDecode(encryptedMetaB64);
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, metaKey, ciphertext);
    return JSON.parse(new TextDecoder().decode(plaintext));
}

function makeChunkIV(baseNonce, seq) {
    const iv = new Uint8Array(baseNonce);
    const view = new DataView(iv.buffer, iv.byteOffset, iv.byteLength);
    // XOR last 4 bytes with sequence number (big-endian)
    const existing = view.getUint32(8, false);
    view.setUint32(8, existing ^ seq, false);
    return iv;
}

async function encryptFile(fileKey, file, onProgress) {
    const baseNonce = crypto.getRandomValues(new Uint8Array(12));
    const chunks = [];
    let seq = 0;
    let offset = 0;

    while (offset < file.size) {
        const end = Math.min(offset + CHUNK_SIZE, file.size);
        const slice = await file.slice(offset, end).arrayBuffer();
        const iv = makeChunkIV(new Uint8Array(baseNonce), seq);
        const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, fileKey, slice);
        // Frame: [4-byte length][ciphertext+tag]
        const frameLen = encrypted.byteLength;
        const frame = new Uint8Array(4 + frameLen);
        new DataView(frame.buffer).setUint32(0, frameLen, false);
        frame.set(new Uint8Array(encrypted), 4);
        chunks.push(frame);
        seq++;
        offset = end;
        if (onProgress) onProgress(offset / file.size);
    }

    // Header: [12-byte baseNonce][4-byte chunkCount]
    const header = new Uint8Array(16);
    header.set(baseNonce);
    new DataView(header.buffer).setUint32(12, seq, false);

    return new Blob([header, ...chunks]);
}

async function decryptFile(fileKey, arrayBuffer, onProgress) {
    const data = new Uint8Array(arrayBuffer);
    const baseNonce = data.slice(0, 12);
    const chunkCount = new DataView(data.buffer, data.byteOffset + 12, 4).getUint32(0, false);

    const plainChunks = [];
    let pos = 16;

    for (let seq = 0; seq < chunkCount; seq++) {
        const frameLen = new DataView(data.buffer, data.byteOffset + pos, 4).getUint32(0, false);
        pos += 4;
        const ciphertext = data.slice(pos, pos + frameLen);
        pos += frameLen;
        const iv = makeChunkIV(new Uint8Array(baseNonce), seq);
        const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, fileKey, ciphertext);
        plainChunks.push(new Uint8Array(plaintext));
        if (onProgress) onProgress((seq + 1) / chunkCount);
    }

    return new Blob(plainChunks);
}

async function encryptText(fileKey, text) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(text);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, fileKey, encoded);
    const combined = new Uint8Array(12 + ciphertext.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(ciphertext), 12);
    return base64urlEncode(combined);
}

async function decryptText(fileKey, encryptedB64) {
    const data = base64urlDecode(encryptedB64);
    const iv = data.slice(0, 12);
    const ciphertext = data.slice(12);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, fileKey, ciphertext);
    return new TextDecoder().decode(plaintext);
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return (bytes / Math.pow(k, i)).toFixed(i > 0 ? 1 : 0) + ' ' + sizes[i];
}
"""


# ============= Web UI: CSS (shared between pages) =============

CSS = """
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
h1 { color: #e040fb; margin-bottom: 10px; font-size: 24px; }
.subtitle { color: #666; margin-bottom: 30px; font-size: 13px; }
.tabs {
    display: flex; gap: 10px; margin-bottom: 30px;
    border-bottom: 2px solid #f0f0f0;
}
.tab {
    flex: 1; padding: 12px; background: none; border: none;
    cursor: pointer; font-size: 15px; color: #666;
    border-bottom: 3px solid transparent; transition: all 0.3s;
}
.tab.active { color: #e040fb; border-bottom-color: #e040fb; font-weight: 600; }
.tab-content { display: none; }
.tab-content.active { display: block; }
.upload-area {
    border: 3px dashed #e0e0e0; border-radius: 12px;
    padding: 40px 20px; text-align: center; cursor: pointer;
    transition: all 0.3s; margin-bottom: 20px;
}
.upload-area:hover, .upload-area.drag-over {
    border-color: #e040fb; background: #fdf2ff;
}
.upload-icon { font-size: 48px; margin-bottom: 10px; }
input[type="text"], input[type="file"] {
    width: 100%; padding: 14px; border: 2px solid #e0e0e0;
    border-radius: 10px; font-size: 15px; margin-bottom: 15px;
    transition: border-color 0.3s; outline: none;
}
input[type="text"]:focus { border-color: #e040fb; }
input[type="file"] { display: none; }
textarea {
    width: 100%; min-height: 140px; padding: 12px;
    border: 2px solid #e0e0e0; border-radius: 10px;
    font-family: monospace; font-size: 14px; resize: vertical;
    box-sizing: border-box; transition: border-color 0.3s; outline: none;
}
textarea:focus { border-color: #e040fb; }
.btn {
    width: 100%; padding: 16px;
    background: linear-gradient(135deg, #e040fb 0%, #00e5ff 100%);
    color: white; border: none; border-radius: 10px;
    font-size: 16px; font-weight: 600; cursor: pointer;
    transition: transform 0.2s, box-shadow 0.2s;
}
.btn:hover:not(:disabled) {
    transform: translateY(-2px);
    box-shadow: 0 10px 20px rgba(224, 64, 251, 0.4);
}
.btn:disabled { opacity: 0.6; cursor: not-allowed; }
.btn-copy {
    background: linear-gradient(135deg, #10b981, #059669);
    margin-top: 10px;
}
.share-url {
    background: #f8f9ff; padding: 15px; border-radius: 10px;
    margin: 15px 0; word-break: break-all; font-family: monospace;
    font-size: 13px; color: #666; user-select: all;
}
.status {
    margin-top: 20px; padding: 15px; border-radius: 10px;
    font-size: 14px; display: none;
}
.status.show { display: block; }
.status.success { background: #d4edda; color: #155724; }
.status.error { background: #f8d7da; color: #721c24; }
.status.info { background: #d1ecf1; color: #0c5460; }
.progress {
    width: 100%; height: 8px; background: #e0e0e0;
    border-radius: 4px; overflow: hidden; margin: 15px 0; display: none;
}
.progress.show { display: block; }
.progress-bar {
    height: 100%;
    background: linear-gradient(90deg, #e040fb, #00e5ff);
    transition: width 0.2s ease; width: 0%;
}
.progress-label {
    font-size: 12px; color: #999; text-align: center;
    margin-bottom: 5px; display: none;
}
.progress-label.show { display: block; }
.badge {
    display: inline-flex; align-items: center; gap: 6px;
    background: #d4edda; color: #155724; padding: 6px 12px;
    border-radius: 15px; font-size: 11px; font-weight: 600;
    margin-top: 15px;
}
.file-info {
    background: #f8f9ff; padding: 15px; border-radius: 10px; margin: 15px 0;
}
.file-info p { margin: 5px 0; font-size: 14px; color: #666; }
.char-counter {
    font-size: 11px; color: #999; text-align: right; margin-top: 4px; margin-bottom: 10px;
}
@media (max-width: 480px) {
    .container { padding: 20px; }
    h1 { font-size: 20px; }
}
"""


# ============= Web UI: Home Page =============

async def index(request):
    nonce = request.get('csp_nonce', '')
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="theme-color" content="#e040fb">
    <title>MagicTransfer</title>
    <link rel="icon" type="image/png" href="/favicon.ico">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="manifest" href="/manifest.json">
    <style nonce="{nonce}">{CSS}</style>
</head>
<body>
    <div class="container">
        <img src="{LOGO_DATA_URI}" width="64" height="64" alt="MagicTransfer" style="display:block;margin:0 auto 10px;">
        <h1 style="text-align:center;">MagicTransfer</h1>
        <p class="subtitle" style="text-align:center;">Zero-knowledge encrypted sharing</p>

        <div class="tabs">
            <button class="tab active" id="tab-send">Send File</button>
            <button class="tab" id="tab-text">Send Text</button>
        </div>

        <!-- SEND TAB -->
        <div id="send-tab" class="tab-content active">
            <div class="upload-area" id="upload-area">
                <div class="upload-icon">&#128193;</div>
                <p><strong>Tap to select file</strong></p>
                <p style="font-size: 12px; color: #999; margin-top: 5px;">or drag & drop</p>
            </div>
            <input type="file" id="file-input">
            <p style="font-size:12px;color:#999;text-align:center;margin-bottom:15px;">Max file size: {MAX_UPLOAD_BYTES // (1024*1024)} MB</p>
            <div id="file-selected" class="file-info" style="display:none">
                <p><strong>File:</strong> <span id="file-name"></span></p>
                <p><strong>Size:</strong> <span id="file-size"></span></p>
            </div>
            <div id="file-error" class="status error" style="display:none;margin-bottom:15px;"></div>
            <textarea id="file-message" rows="3" maxlength="4000" placeholder="Add a message (optional)" style="min-height:auto;margin-bottom:15px;display:none;"></textarea>
            <button class="btn" id="send-btn" disabled>Encrypt & Upload</button>
            <div id="send-progress-label" class="progress-label"></div>
            <div id="send-progress" class="progress"><div id="send-progress-bar" class="progress-bar"></div></div>
            <div id="send-result" style="display:none">
                <h3 style="text-align:center;color:#666;margin-top:20px;font-size:14px;">Share this link:</h3>
                <div class="share-url" id="share-url"></div>
                <button class="btn btn-copy" id="copy-link-btn">Copy Link</button>
            </div>
            <div id="send-status" class="status"></div>
        </div>

        <!-- TEXT TAB -->
        <div id="text-tab" class="tab-content">
            <textarea id="text-input" placeholder="Paste passwords, credentials, or any text..." maxlength="50000"></textarea>
            <div class="char-counter" id="char-counter">0 / 50,000</div>
            <button class="btn" id="text-btn" disabled>Encrypt & Share</button>
            <div id="text-progress-label" class="progress-label"></div>
            <div id="text-progress" class="progress"><div id="text-progress-bar" class="progress-bar"></div></div>
            <div id="text-result" style="display:none">
                <h3 style="text-align:center;color:#666;margin-top:20px;font-size:14px;">Share this link:</h3>
                <div class="share-url" id="text-share-url"></div>
                <button class="btn btn-copy" id="copy-text-link-btn">Copy Link</button>
            </div>
            <div id="text-status" class="status"></div>
        </div>

        <div class="badge">&#128274; Zero-knowledge &middot; AES-256-GCM &middot; Browser-encrypted</div>
    </div>

    <script nonce="{nonce}">
    {CRYPTO_JS}

    // ============= UI Logic =============

    let selectedFile = null;

    function switchTab(tab) {{
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        if (tab === 'send') {{
            document.querySelector('.tab:first-child').classList.add('active');
            document.getElementById('send-tab').classList.add('active');
        }} else {{
            document.querySelector('.tab:last-child').classList.add('active');
            document.getElementById('text-tab').classList.add('active');
        }}
    }}

    const MAX_FILE_SIZE = {MAX_UPLOAD_BYTES};

    function handleFileSelect(event) {{
        selectedFile = event.target.files[0];
        if (selectedFile) {{
            document.getElementById('file-name').textContent = selectedFile.name;
            document.getElementById('file-size').textContent = formatBytes(selectedFile.size);
            document.getElementById('file-selected').style.display = 'block';
            const errEl = document.getElementById('file-error');
            if (selectedFile.size > MAX_FILE_SIZE) {{
                errEl.textContent = 'File exceeds the ' + formatBytes(MAX_FILE_SIZE) + ' size limit.';
                errEl.style.display = 'block';
                document.getElementById('send-btn').disabled = true;
                document.getElementById('file-message').style.display = 'none';
            }} else {{
                errEl.style.display = 'none';
                document.getElementById('send-btn').disabled = false;
                document.getElementById('file-message').style.display = 'block';
            }}
        }}
    }}

    // Drag & drop
    const uploadArea = document.getElementById('upload-area');
    uploadArea.addEventListener('dragover', e => {{ e.preventDefault(); uploadArea.classList.add('drag-over'); }});
    uploadArea.addEventListener('dragleave', () => uploadArea.classList.remove('drag-over'));
    uploadArea.addEventListener('drop', e => {{
        e.preventDefault();
        uploadArea.classList.remove('drag-over');
        if (e.dataTransfer.files.length) {{
            document.getElementById('file-input').files = e.dataTransfer.files;
            handleFileSelect({{ target: {{ files: e.dataTransfer.files }} }});
        }}
    }});

    function showStatus(id, type, msg) {{
        const el = document.getElementById(id);
        el.className = 'status show ' + type;
        el.textContent = msg;
    }}

    function showProgress(prefix, pct, label) {{
        const bar = document.getElementById(prefix + '-progress-bar');
        const wrap = document.getElementById(prefix + '-progress');
        const lbl = document.getElementById(prefix + '-progress-label');
        bar.style.width = (pct * 100) + '%';
        wrap.classList.add('show');
        if (label) {{ lbl.textContent = label; lbl.classList.add('show'); }}
    }}

    function hideProgress(prefix) {{
        document.getElementById(prefix + '-progress').classList.remove('show');
        document.getElementById(prefix + '-progress-label').classList.remove('show');
    }}

    async function doUpload() {{
        if (!selectedFile) return;
        const btn = document.getElementById('send-btn');
        btn.disabled = true;
        btn.textContent = 'Encrypting...';

        try {{
            // 1. Generate keys
            const ikm = await generateIKM();
            const {{ fileKey, metaKey, authToken }} = await deriveKeys(ikm);

            // 2. Encrypt metadata
            const metaObj = {{
                name: selectedFile.name,
                size: selectedFile.size,
                type: selectedFile.type || 'application/octet-stream'
            }};
            const fileMsg = document.getElementById('file-message').value.trim();
            if (fileMsg) metaObj.message = fileMsg;
            const encMeta = await encryptMeta(metaKey, metaObj);

            // 3. Encrypt file
            showProgress('send', 0, 'Encrypting...');
            const encBlob = await encryptFile(fileKey, selectedFile, pct => showProgress('send', pct * 0.5, 'Encrypting...'));

            // 4. Upload
            showProgress('send', 0.5, 'Uploading...');
            const form = new FormData();
            form.append('blob', encBlob, 'encrypted.bin');
            form.append('meta', encMeta);
            form.append('auth_token', authToken);

            const resp = await fetch('/api/upload', {{ method: 'POST', body: form }});

            if (!resp.ok) {{
                const err = await resp.json();
                throw new Error(err.error || 'Upload failed');
            }}

            showProgress('send', 1, 'Done!');
            const {{ file_id }} = await resp.json();

            // 5. Show share URL
            const shareUrl = location.origin + '/d/' + file_id + '#' + base64urlEncode(ikm);
            document.getElementById('share-url').textContent = shareUrl;
            document.getElementById('send-result').style.display = 'block';
            hideProgress('send');
            btn.textContent = 'Encrypt & Upload';
            showStatus('send-status', 'success', 'File encrypted and uploaded. Share the link!');
        }} catch (err) {{
            hideProgress('send');
            btn.disabled = false;
            btn.textContent = 'Encrypt & Upload';
            showStatus('send-status', 'error', err.message);
        }}
    }}

    function copyLink() {{
        const url = document.getElementById('share-url').textContent;
        navigator.clipboard.writeText(url).then(() => {{
            showStatus('send-status', 'success', 'Link copied to clipboard!');
        }});
    }}

    function updateCharCounter() {{
        const text = document.getElementById('text-input').value;
        document.getElementById('char-counter').textContent = text.length.toLocaleString() + ' / 50,000';
        document.getElementById('text-btn').disabled = text.length === 0;
    }}

    async function doTextShare() {{
        const text = document.getElementById('text-input').value.trim();
        if (!text) return;
        const btn = document.getElementById('text-btn');
        btn.disabled = true;
        btn.textContent = 'Encrypting...';

        try {{
            const ikm = await generateIKM();
            const {{ fileKey, metaKey, authToken }} = await deriveKeys(ikm);

            const encText = await encryptText(fileKey, text);
            const encMeta = await encryptMeta(metaKey, {{ type: 'text', size: text.length }});

            showProgress('text', 0.5, 'Uploading...');
            const resp = await fetch('/api/text', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ encrypted_text: encText, meta: encMeta, auth_token: authToken }})
            }});

            if (!resp.ok) {{
                const err = await resp.json();
                throw new Error(err.error || 'Share failed');
            }}

            showProgress('text', 1, 'Done!');
            const {{ file_id }} = await resp.json();

            const shareUrl = location.origin + '/d/' + file_id + '#' + base64urlEncode(ikm);
            document.getElementById('text-share-url').textContent = shareUrl;
            document.getElementById('text-result').style.display = 'block';
            hideProgress('text');
            btn.textContent = 'Encrypt & Share';
            showStatus('text-status', 'success', 'Text encrypted and stored. Share the link!');
        }} catch (err) {{
            hideProgress('text');
            btn.disabled = false;
            btn.textContent = 'Encrypt & Share';
            showStatus('text-status', 'error', err.message);
        }}
    }}

    function copyTextLink() {{
        const url = document.getElementById('text-share-url').textContent;
        navigator.clipboard.writeText(url).then(() => {{
            showStatus('text-status', 'success', 'Link copied to clipboard!');
        }});
    }}

    // Event listeners (CSP blocks inline onclick handlers)
    document.getElementById('tab-send').addEventListener('click', () => switchTab('send'));
    document.getElementById('tab-text').addEventListener('click', () => switchTab('text'));
    document.getElementById('upload-area').addEventListener('click', () => document.getElementById('file-input').click());
    document.getElementById('file-input').addEventListener('change', handleFileSelect);
    document.getElementById('send-btn').addEventListener('click', doUpload);
    document.getElementById('copy-link-btn').addEventListener('click', copyLink);
    document.getElementById('text-input').addEventListener('input', updateCharCounter);
    document.getElementById('text-btn').addEventListener('click', doTextShare);
    document.getElementById('copy-text-link-btn').addEventListener('click', copyTextLink);
    </script>
</body>
</html>"""
    return web.Response(text=html, content_type='text/html')


# ============= Web UI: Download Page =============

async def download_page(request):
    file_id = request.match_info['file_id']
    if not re.fullmatch(r'[A-Za-z0-9_-]{16,32}', file_id):
        return web.json_response({'error': 'Invalid file ID'}, status=400)
    nonce = request.get('csp_nonce', '')

    # Verify the file_id exists (don't leak whether it's valid or not via timing)
    session = store.get_session(file_id)

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="theme-color" content="#e040fb">
    <title>MagicTransfer - Download</title>
    <link rel="icon" type="image/png" href="/favicon.ico">
    <style nonce="{nonce}">{CSS}</style>
</head>
<body>
    <div class="container">
        <img src="{LOGO_DATA_URI}" width="64" height="64" alt="MagicTransfer" style="display:block;margin:0 auto 10px;">
        <h1 style="text-align:center;">MagicTransfer</h1>
        <p class="subtitle" style="text-align:center;">Zero-knowledge encrypted sharing</p>

        <div id="loading" style="text-align:center;padding:40px 0;">
            <div style="font-size:32px;margin-bottom:15px;">&#9881;&#65039;</div>
            <p style="color:#666;">Decrypting...</p>
        </div>

        <div id="error-view" style="display:none;text-align:center;padding:20px 0;">
            <div style="font-size:48px;margin-bottom:15px;">&#128683;</div>
            <p id="error-msg" style="color:#721c24;font-weight:600;"></p>
        </div>

        <div id="file-view" style="display:none;">
            <div id="dl-message" style="display:none;background:#f0e6ff;padding:15px;border-radius:10px;margin-bottom:15px;border-left:4px solid #e040fb;">
                <p style="font-size:12px;color:#999;margin-bottom:4px;">Message from sender:</p>
                <p id="dl-message-text" style="color:#333;white-space:pre-wrap;"></p>
            </div>
            <div class="file-info">
                <p><strong>File:</strong> <span id="dl-name"></span></p>
                <p><strong>Size:</strong> <span id="dl-size"></span></p>
            </div>
            <button class="btn" id="dl-btn" style="margin-top:15px;">Download File</button>
            <div id="dl-progress-label" class="progress-label"></div>
            <div id="dl-progress" class="progress"><div id="dl-progress-bar" class="progress-bar"></div></div>
            <div id="dl-status" class="status"></div>
        </div>

        <div id="text-view" style="display:none;">
            <textarea id="decrypted-text" readonly style="min-height:200px;background:#f8f9ff;"></textarea>
            <button class="btn btn-copy" id="copy-text-btn" style="margin-top:15px;">Copy Text</button>
            <div id="text-dl-status" class="status"></div>
        </div>

        <div class="badge" style="margin-top:20px;">&#128274; Decrypted in your browser &middot; Server never sees your data</div>
    </div>

    <script nonce="{nonce}">
    {CRYPTO_JS}

    const FILE_ID = {json.dumps(file_id)};

    function showError(msg) {{
        document.getElementById('loading').style.display = 'none';
        document.getElementById('error-view').style.display = 'block';
        document.getElementById('error-msg').textContent = msg;
    }}

    function showDlProgress(pct, label) {{
        const bar = document.getElementById('dl-progress-bar');
        const wrap = document.getElementById('dl-progress');
        const lbl = document.getElementById('dl-progress-label');
        bar.style.width = (pct * 100) + '%';
        wrap.classList.add('show');
        if (label) {{ lbl.textContent = label; lbl.classList.add('show'); }}
    }}

    function copyDecryptedText() {{
        const text = document.getElementById('decrypted-text').value;
        navigator.clipboard.writeText(text).then(() => {{
            const s = document.getElementById('text-dl-status');
            s.className = 'status show success';
            s.textContent = 'Copied to clipboard!';
        }});
    }}

    document.getElementById('copy-text-btn').addEventListener('click', copyDecryptedText);

    async function main() {{
        // 1. Extract key from URL fragment
        const hash = window.location.hash.substring(1);
        if (!hash) {{
            showError('Invalid or missing decryption key. Make sure you have the complete link.');
            return;
        }}

        // Strip fragment from URL bar immediately
        history.replaceState(null, '', window.location.pathname);

        let ikm;
        try {{
            ikm = base64urlDecode(hash);
            if (ikm.length !== 32) throw new Error('Invalid key length');
        }} catch (e) {{
            showError('Invalid decryption key in the link.');
            return;
        }}

        // 2. Derive keys
        let fileKey, metaKey, authToken;
        try {{
            ({{ fileKey, metaKey, authToken }} = await deriveKeys(ikm));
        }} catch (e) {{
            showError('Failed to derive encryption keys.');
            return;
        }}

        // 3. Fetch session info
        let info;
        try {{
            const resp = await fetch('/api/info/' + FILE_ID, {{
                headers: {{ 'Authorization': 'Bearer ' + authToken }}
            }});
            if (resp.status === 401) {{
                showError('Invalid decryption key. The link may be incorrect.');
                return;
            }}
            if (resp.status === 404) {{
                showError('This transfer has expired or already been downloaded.');
                return;
            }}
            if (!resp.ok) throw new Error('Server error');
            info = await resp.json();
        }} catch (e) {{
            showError(e.message || 'Failed to connect to server.');
            return;
        }}

        if (info.status === 'downloaded') {{
            showError('This transfer has already been downloaded (burn-after-read).');
            return;
        }}

        // 4. Decrypt metadata
        let meta;
        try {{
            meta = await decryptMeta(metaKey, info.encrypted_meta);
        }} catch (e) {{
            showError('Failed to decrypt metadata. The link may be corrupted.');
            return;
        }}

        document.getElementById('loading').style.display = 'none';

        // 5. Handle by content type
        if (info.content_type === 'text') {{
            // Text download
            try {{
                const resp = await fetch('/api/text/' + FILE_ID, {{
                    headers: {{ 'Authorization': 'Bearer ' + authToken }}
                }});
                if (!resp.ok) throw new Error('Failed to fetch text');
                const data = await resp.json();
                const plaintext = await decryptText(fileKey, data.encrypted_text);
                document.getElementById('text-view').style.display = 'block';
                document.getElementById('decrypted-text').value = plaintext;

                // Burn after read
                await fetch('/api/complete/' + FILE_ID, {{
                    method: 'POST',
                    headers: {{ 'Authorization': 'Bearer ' + authToken }}
                }});
            }} catch (e) {{
                showError('Failed to decrypt text: ' + e.message);
            }}
        }} else {{
            // File download — show info and wait for user to click download
            document.getElementById('file-view').style.display = 'block';
            document.getElementById('dl-name').textContent = meta.name || 'unknown';
            document.getElementById('dl-size').textContent = formatBytes(meta.size || 0);

            if (meta.message) {{
                document.getElementById('dl-message').style.display = 'block';
                document.getElementById('dl-message-text').textContent = meta.message;
            }}

            document.getElementById('dl-btn').addEventListener('click', async function() {{
                const btn = document.getElementById('dl-btn');
                btn.disabled = true;
                btn.textContent = 'Downloading...';

                try {{
                    showDlProgress(0, 'Downloading...');
                    const resp = await fetch('/api/download/' + FILE_ID, {{
                        headers: {{ 'Authorization': 'Bearer ' + authToken }}
                    }});
                    if (!resp.ok) throw new Error('Download failed');

                    const encryptedData = await resp.arrayBuffer();
                    showDlProgress(0.5, 'Decrypting...');

                    const decryptedBlob = await decryptFile(fileKey, encryptedData, pct => {{
                        showDlProgress(0.5 + pct * 0.5, 'Decrypting...');
                    }});

                    const url = URL.createObjectURL(decryptedBlob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = meta.name || 'download';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);

                    showDlProgress(1, 'Complete!');
                    const s = document.getElementById('dl-status');
                    s.className = 'status show success';
                    s.textContent = 'File decrypted and downloaded successfully.';
                    btn.style.display = 'none';

                    await fetch('/api/complete/' + FILE_ID, {{
                        method: 'POST',
                        headers: {{ 'Authorization': 'Bearer ' + authToken }}
                    }});
                }} catch (e) {{
                    showDlProgress(0, '');
                    const s = document.getElementById('dl-status');
                    s.className = 'status show error';
                    s.textContent = 'Decryption failed: ' + e.message;
                    btn.disabled = false;
                    btn.textContent = 'Download File';
                }}
            }});
        }}
    }}

    main();
    </script>
</body>
</html>"""
    return web.Response(text=html, content_type='text/html')


# ============= Middleware =============

@web.middleware
async def request_logging_middleware(request, handler):
    start = time.time()
    try:
        response = await handler(request)
        duration = (time.time() - start) * 1000
        if request.path not in ('/health', '/favicon.ico'):
            logger.info(
                f"{request.method} {request.path} {response.status} {duration:.0f}ms",
                extra={
                    'client_ip': _get_client_ip(request),
                    'method': request.method,
                    'path': request.path,
                    'status': response.status,
                    'duration_ms': round(duration),
                })
        return response
    except web.HTTPException:
        raise
    except Exception:
        logger.exception(f"Unhandled error: {request.method} {request.path}")
        raise


@web.middleware
async def security_headers_middleware(request, handler):
    nonce = secrets.token_urlsafe(16)
    request['csp_nonce'] = nonce
    response = await handler(request)
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['Content-Security-Policy'] = (
        f"default-src 'self'; "
        f"script-src 'nonce-{nonce}'; "
        f"style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data:; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none'"
    )
    return response


@web.middleware
async def timeout_middleware(request, handler):
    try:
        return await asyncio.wait_for(handler(request), timeout=120)
    except asyncio.TimeoutError:
        return web.json_response({'error': 'Request timeout'}, status=504)


# ============= Background Tasks =============

async def periodic_cleanup(app):
    while True:
        await asyncio.sleep(300)  # every 5 minutes
        try:
            store.cleanup_expired()
            store.upload_limiter.cleanup()
            store.download_limiter.cleanup()
        except Exception as e:
            logger.error(f"Cleanup error: {e}")


async def start_background_tasks(app):
    app['cleanup_task'] = asyncio.create_task(periodic_cleanup(app))


async def cleanup_background_tasks(app):
    app['cleanup_task'].cancel()
    try:
        await app['cleanup_task']
    except asyncio.CancelledError:
        pass


# ============= App Factory =============

def create_app():
    app = web.Application(
        client_max_size=MAX_UPLOAD_BYTES + 1024 * 1024,
        middlewares=[
            request_logging_middleware,
            timeout_middleware,
            security_headers_middleware,
        ],
    )

    # API routes
    app.router.add_get('/health', health_check)
    app.router.add_post('/api/upload', upload_file)
    app.router.add_post('/api/text', create_text)
    app.router.add_get('/api/info/{file_id}', get_info)
    app.router.add_get('/api/download/{file_id}', download_file)
    app.router.add_get('/api/text/{file_id}', get_text)
    app.router.add_post('/api/complete/{file_id}', complete_transfer)
    app.router.add_get('/metrics', metrics)

    # Icon / PWA routes
    app.router.add_get('/favicon.ico', favicon_ico)
    app.router.add_get('/apple-touch-icon.png', apple_touch_icon)
    app.router.add_get('/apple-touch-icon-precomposed.png', apple_touch_icon)
    app.router.add_get('/icon-192.png', icon_192)
    app.router.add_get('/icon-512.png', icon_512)
    app.router.add_get('/manifest.json', manifest_json)

    # Web UI routes
    app.router.add_get('/', index)
    app.router.add_get('/d/{file_id}', download_page)

    # Background tasks
    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)

    return app


if __name__ == '__main__':
    port = int(os.environ.get('PORT', '8080'))
    app = create_app()
    logger.info(f"MagicTransfer v3.0 starting on port {port}")
    web.run_app(app, host='0.0.0.0', port=port)
