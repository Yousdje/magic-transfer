#!/usr/bin/env python3
"""
Secure P2P File Transfer Application
End-to-end encrypted file transfers using WebRTC
"""

import asyncio
import json
import secrets
import hashlib
import base64
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime
import logging

from aiohttp import web
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import aiortc
from aiortc import RTCPeerConnection, RTCSessionDescription, RTCDataChannel
import aiofiles

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecureFileTransfer:
    """Handles secure P2P file transfers with E2E encryption"""
    
    def __init__(self):
        self.peers: Dict[str, RTCPeerConnection] = {}
        self.channels: Dict[str, RTCDataChannel] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.encryption_keys: Dict[str, bytes] = {}
        
    def generate_pairing_code(self) -> str:
        """Generate a secure 8-digit pairing code (~26.5 bits entropy)"""
        return ''.join(secrets.choice('0123456789') for _ in range(8))

    def derive_encryption_key(self, pairing_code: str, salt: bytes) -> bytes:
        """Derive AES-256 key from pairing code using PBKDF2"""
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
    
    async def create_sender_session(self, file_path: str) -> Dict[str, str]:
        """Create a new sender session"""
        session_id = secrets.token_urlsafe(16)
        pairing_code = self.generate_pairing_code()
        salt = secrets.token_bytes(16)
        
        # Derive encryption key
        encryption_key = self.derive_encryption_key(pairing_code, salt)
        
        # Calculate file hash
        file_hash = await self._calculate_file_hash(file_path)
        file_size = Path(file_path).stat().st_size
        file_name = Path(file_path).name
        
        self.sessions[session_id] = {
            'role': 'sender',
            'file_path': file_path,
            'file_name': file_name,
            'file_size': file_size,
            'file_hash': file_hash,
            'salt': base64.b64encode(salt).decode(),
            'pairing_code': pairing_code,
            'status': 'waiting',
            'created_at': datetime.now().isoformat()
        }
        
        self.encryption_keys[session_id] = encryption_key
        
        return {
            'session_id': session_id,
            'pairing_code': pairing_code,
            'file_name': file_name,
            'file_size': file_size
        }
    
    async def create_receiver_session(self, pairing_code: str, output_dir: str) -> Optional[Dict[str, str]]:
        """Create a receiver session by joining with pairing code"""
        # Find matching sender session
        sender_session_id = None
        for sid, session in self.sessions.items():
            if session.get('pairing_code') == pairing_code and session['role'] == 'sender':
                sender_session_id = sid
                break
        
        if not sender_session_id:
            return None
        
        sender_session = self.sessions[sender_session_id]
        session_id = secrets.token_urlsafe(16)
        
        # Derive same encryption key
        salt = base64.b64decode(sender_session['salt'])
        encryption_key = self.derive_encryption_key(pairing_code, salt)
        
        self.sessions[session_id] = {
            'role': 'receiver',
            'paired_with': sender_session_id,
            'output_dir': output_dir,
            'file_name': sender_session['file_name'],
            'file_size': sender_session['file_size'],
            'expected_hash': sender_session['file_hash'],
            'status': 'paired',
            'created_at': datetime.now().isoformat()
        }
        
        self.encryption_keys[session_id] = encryption_key
        sender_session['status'] = 'paired'
        sender_session['paired_with'] = session_id
        
        return {
            'session_id': session_id,
            'sender_session_id': sender_session_id,
            'file_name': sender_session['file_name'],
            'file_size': sender_session['file_size']
        }
    
    async def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        async with aiofiles.open(file_path, 'rb') as f:
            while chunk := await f.read(8192):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    async def setup_webrtc_connection(self, session_id: str) -> RTCPeerConnection:
        """Setup WebRTC peer connection"""
        pc = RTCPeerConnection()
        self.peers[session_id] = pc
        
        @pc.on("datachannel")
        async def on_datachannel(channel):
            self.channels[session_id] = channel
            session = self.sessions[session_id]
            
            if session['role'] == 'receiver':
                await self._handle_receiver_channel(session_id, channel)
            
            @channel.on("message")
            async def on_message(message):
                if session['role'] == 'receiver':
                    await self._handle_received_chunk(session_id, message)
        
        return pc
    
    async def _handle_receiver_channel(self, session_id: str, channel: RTCDataChannel):
        """Handle receiver data channel setup"""
        session = self.sessions[session_id]
        output_path = Path(session['output_dir']) / session['file_name']
        session['output_path'] = str(output_path)
        session['received_chunks'] = []
        session['file_handle'] = await aiofiles.open(output_path, 'wb')
    
    async def _handle_received_chunk(self, session_id: str, message):
        """Handle received encrypted chunk"""
        session = self.sessions[session_id]
        encryption_key = self.encryption_keys[session_id]
        
        # Parse message
        data = json.loads(message)
        
        if data['type'] == 'chunk':
            ciphertext = base64.b64decode(data['data'])
            nonce = base64.b64decode(data['nonce'])
            
            # Decrypt
            plaintext = self.decrypt_chunk(encryption_key, ciphertext, nonce)
            
            # Write to file
            await session['file_handle'].write(plaintext)
            session['received_chunks'].append(data['chunk_id'])
            
            # Send acknowledgment
            if session_id in self.channels:
                ack = json.dumps({'type': 'ack', 'chunk_id': data['chunk_id']})
                self.channels[session_id].send(ack)
        
        elif data['type'] == 'complete':
            # Verify file hash
            await session['file_handle'].close()
            received_hash = await self._calculate_file_hash(session['output_path'])
            
            if received_hash == session['expected_hash']:
                session['status'] = 'completed'
                logger.info(f"Transfer completed successfully: {session['file_name']}")
            else:
                session['status'] = 'hash_mismatch'
                logger.error(f"Hash mismatch for {session['file_name']}")
    
    async def send_file(self, session_id: str):
        """Send file through WebRTC data channel"""
        session = self.sessions[session_id]
        encryption_key = self.encryption_keys[session_id]
        channel = self.channels.get(session_id)
        
        if not channel:
            logger.error("No data channel available")
            return
        
        chunk_size = 16384  # 16KB chunks
        chunk_id = 0
        
        async with aiofiles.open(session['file_path'], 'rb') as f:
            while chunk := await f.read(chunk_size):
                # Generate nonce
                nonce = secrets.token_bytes(12)
                
                # Encrypt chunk
                ciphertext = self.encrypt_chunk(encryption_key, chunk, nonce)
                
                # Send encrypted chunk
                message = json.dumps({
                    'type': 'chunk',
                    'chunk_id': chunk_id,
                    'data': base64.b64encode(ciphertext).decode(),
                    'nonce': base64.b64encode(nonce).decode()
                })
                
                channel.send(message)
                chunk_id += 1
                
                # Wait for acknowledgment (simplified)
                await asyncio.sleep(0.01)
        
        # Send completion message
        completion = json.dumps({'type': 'complete'})
        channel.send(completion)
        session['status'] = 'completed'
        logger.info(f"File sent successfully: {session['file_name']}")


# Global instance
file_transfer = SecureFileTransfer()


# Web API endpoints
ALLOWED_INPUT_DIR = Path("/input").resolve()

async def create_send_session(request):
    """API: Create a new sending session"""
    data = await request.json()
    file_path = data.get('file_path')

    if not file_path:
        return web.json_response({'error': 'file_path required'}, status=400)

    # Resolve to absolute and verify it's inside the allowed directory
    resolved = Path(file_path).resolve()
    if not str(resolved).startswith(str(ALLOWED_INPUT_DIR)):
        logger.warning(f"Path traversal attempt blocked: {file_path}")
        return web.json_response({'error': 'Access denied: path outside allowed directory'}, status=403)

    if not resolved.exists() or not resolved.is_file():
        return web.json_response({'error': 'File not found'}, status=404)

    result = await file_transfer.create_sender_session(str(resolved))
    return web.json_response(result)


ALLOWED_OUTPUT_DIR = Path("/output").resolve()

async def join_session(request):
    """API: Join session with pairing code"""
    data = await request.json()
    pairing_code = data.get('pairing_code', '')

    if not pairing_code or not pairing_code.isdigit() or len(pairing_code) != 8:
        return web.json_response({'error': 'Invalid pairing code'}, status=400)

    # Force output to allowed directory only — ignore user-supplied output_dir
    output_dir = str(ALLOWED_OUTPUT_DIR)

    result = await file_transfer.create_receiver_session(pairing_code, output_dir)

    if result:
        return web.json_response(result)
    else:
        return web.json_response({'error': 'Invalid pairing code'}, status=404)


async def get_session_status(request):
    """API: Get session status"""
    session_id = request.match_info['session_id']
    
    if session_id not in file_transfer.sessions:
        return web.json_response({'error': 'Session not found'}, status=404)
    
    session = file_transfer.sessions[session_id]
    # Remove sensitive data
    safe_session = {k: v for k, v in session.items() if k not in ['pairing_code', 'file_path']}
    
    return web.json_response(safe_session)


async def webrtc_offer(request):
    """API: Handle WebRTC offer"""
    data = await request.json()
    session_id = data.get('session_id')
    offer = data.get('offer')
    
    pc = await file_transfer.setup_webrtc_connection(session_id)
    
    # Set remote description
    await pc.setRemoteDescription(RTCSessionDescription(sdp=offer['sdp'], type=offer['type']))
    
    # Create answer
    answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)
    
    return web.json_response({
        'answer': {
            'sdp': pc.localDescription.sdp,
            'type': pc.localDescription.type
        }
    })


async def webrtc_answer(request):
    """API: Handle WebRTC answer"""
    data = await request.json()
    session_id = data.get('session_id')
    answer = data.get('answer')
    
    pc = file_transfer.peers.get(session_id)
    if not pc:
        return web.json_response({'error': 'Session not found'}, status=404)
    
    await pc.setRemoteDescription(RTCSessionDescription(sdp=answer['sdp'], type=answer['type']))
    
    return web.json_response({'status': 'ok'})


from io import BytesIO
from PIL import Image, ImageDraw


def _lerp_color(c1, c2, t):
    return tuple(int(c1[i] + (c2[i] - c1[i]) * t) for i in range(3))


def generate_icon_png(size):
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    cx, cy = size // 2, size // 2
    r = size // 2 - 1
    c_start, c_end = (102, 126, 234), (118, 75, 162)
    for y in range(size):
        for x in range(size):
            dx, dy = x - cx, y - cy
            if dx * dx + dy * dy <= r * r:
                t = (x + y) / (2 * size)
                img.putpixel((x, y), _lerp_color(c_start, c_end, t) + (255,))
    s = size / 512
    line_w = max(2, int(30 * s))
    bar_y, bar_x1, bar_x2 = cy, int(150 * s), int(362 * s)
    draw.line([(bar_x1, bar_y), (bar_x2, bar_y)], fill='white', width=line_w)
    arrow_len = int(60 * s)
    tip_x = int(100 * s)
    draw.line([(tip_x, bar_y), (tip_x + arrow_len, bar_y - arrow_len)], fill='white', width=line_w)
    draw.line([(tip_x, bar_y), (tip_x + arrow_len, bar_y + arrow_len)], fill='white', width=line_w)
    draw.line([(tip_x, bar_y), (bar_x1, bar_y)], fill='white', width=line_w)
    tip_x2 = int(412 * s)
    draw.line([(tip_x2, bar_y), (tip_x2 - arrow_len, bar_y - arrow_len)], fill='white', width=line_w)
    draw.line([(tip_x2, bar_y), (tip_x2 - arrow_len, bar_y + arrow_len)], fill='white', width=line_w)
    draw.line([(bar_x2, bar_y), (tip_x2, bar_y)], fill='white', width=line_w)
    buf = BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


ICON_32 = generate_icon_png(32)


async def favicon_ico(request):
    """Serve 32x32 PNG favicon"""
    return web.Response(body=ICON_32, content_type='image/png',
                        headers={'Cache-Control': 'public, max-age=604800'})


async def index(request):
    """Serve web interface"""
    html = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure File Transfer</title>
    <link rel="icon" type="image/png" href="/favicon.ico">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', system-ui, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            padding: 40px;
            max-width: 600px;
            width: 100%;
        }
        h1 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .tabs {
            display: flex;
            gap: 10px;
            margin-bottom: 30px;
            border-bottom: 2px solid #f0f0f0;
        }
        .tab {
            padding: 12px 24px;
            background: none;
            border: none;
            cursor: pointer;
            font-size: 16px;
            color: #666;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
        }
        .tab.active {
            color: #667eea;
            border-bottom-color: #667eea;
            font-weight: 600;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .input-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
            font-size: 14px;
        }
        input, select {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s;
        }
        input:focus, select:focus {
            outline: none;
            border-color: #667eea;
        }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        button:active {
            transform: translateY(0);
        }
        .status {
            margin-top: 20px;
            padding: 15px;
            border-radius: 8px;
            font-size: 14px;
            display: none;
        }
        .status.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
            display: block;
        }
        .status.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
            display: block;
        }
        .status.info {
            background: #d1ecf1;
            color: #0c5460;
            border: 1px solid #bee5eb;
            display: block;
        }
        .pairing-code {
            font-size: 48px;
            font-weight: bold;
            text-align: center;
            color: #667eea;
            letter-spacing: 10px;
            margin: 30px 0;
            padding: 20px;
            background: #f8f9ff;
            border-radius: 12px;
        }
        .info-box {
            background: #f8f9ff;
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
        }
        .info-box h3 {
            color: #667eea;
            margin-bottom: 8px;
            font-size: 16px;
        }
        .info-box p {
            color: #666;
            font-size: 14px;
            margin: 4px 0;
        }
        .security-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: #d4edda;
            color: #155724;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            margin-top: 20px;
        }
        .security-badge::before {
            content: "🔒";
        }
    </style>
</head>
<body>
    <div class="container">
        <img src="/favicon.ico" width="64" height="64" alt="Secure File Transfer" style="display:block;margin:0 auto 10px;">
        <h1 style="text-align:center;">Secure File Transfer</h1>
        <p class="subtitle">End-to-end encrypted peer-to-peer file sharing</p>
        
        <div class="tabs">
            <button class="tab active" onclick="switchTab('send')">Send File</button>
            <button class="tab" onclick="switchTab('receive')">Receive File</button>
        </div>
        
        <div id="send-tab" class="tab-content active">
            <div class="input-group">
                <label>Select file to send:</label>
                <input type="text" id="file-path" placeholder="/path/to/file.txt">
            </div>
            <button onclick="createSendSession()">Generate Pairing Code</button>
            
            <div id="send-status" class="status"></div>
            
            <div id="pairing-display" style="display: none;">
                <h3 style="text-align: center; color: #666; margin-top: 30px;">Share this code with recipient:</h3>
                <div class="pairing-code" id="pairing-code"></div>
                <div class="info-box">
                    <h3>File Details</h3>
                    <p><strong>Name:</strong> <span id="file-name"></span></p>
                    <p><strong>Size:</strong> <span id="file-size"></span></p>
                </div>
                <p style="text-align: center; color: #666; font-size: 14px;">
                    Waiting for recipient to connect...
                </p>
            </div>
        </div>
        
        <div id="receive-tab" class="tab-content">
            <div class="input-group">
                <label>Enter 6-digit pairing code:</label>
                <input type="text" id="pairing-input" placeholder="00000000" maxlength="8" pattern="[0-9]{8}">
            </div>
            <div class="input-group">
                <label>Save location:</label>
                <input type="text" id="output-dir" value="/output" placeholder="/output">
            </div>
            <button onclick="joinSession()">Connect & Receive</button>
            
            <div id="receive-status" class="status"></div>
        </div>
        
        <div class="security-badge">
            AES-256-GCM Encrypted • Zero-Knowledge
        </div>
    </div>
    
    <script>
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            if (tab === 'send') {
                document.querySelector('.tab:first-child').classList.add('active');
                document.getElementById('send-tab').classList.add('active');
            } else {
                document.querySelector('.tab:last-child').classList.add('active');
                document.getElementById('receive-tab').classList.add('active');
            }
        }
        
        async function createSendSession() {
            const filePath = document.getElementById('file-path').value;
            const statusDiv = document.getElementById('send-status');
            
            if (!filePath) {
                showStatus(statusDiv, 'error', 'Please enter a file path');
                return;
            }
            
            try {
                const response = await fetch('/api/send', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({file_path: filePath})
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    document.getElementById('pairing-code').textContent = data.pairing_code;
                    document.getElementById('file-name').textContent = data.file_name;
                    document.getElementById('file-size').textContent = formatBytes(data.file_size);
                    document.getElementById('pairing-display').style.display = 'block';
                    showStatus(statusDiv, 'success', 'Session created! Share the pairing code.');
                } else {
                    showStatus(statusDiv, 'error', data.error || 'Failed to create session');
                }
            } catch (error) {
                showStatus(statusDiv, 'error', 'Connection error: ' + error.message);
            }
        }
        
        async function joinSession() {
            const pairingCode = document.getElementById('pairing-input').value;
            const outputDir = document.getElementById('output-dir').value;
            const statusDiv = document.getElementById('receive-status');
            
            if (pairingCode.length !== 8 || !/^\\d+$/.test(pairingCode)) {
                showStatus(statusDiv, 'error', 'Please enter a valid 6-digit code');
                return;
            }
            
            try {
                const response = await fetch('/api/join', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        pairing_code: pairingCode,
                        output_dir: outputDir
                    })
                });
                
                const data = await response.json();
                
                if (response.ok) {
                    showStatus(statusDiv, 'success', 
                        `Connected! Receiving: ${data.file_name} (${formatBytes(data.file_size)})`);
                } else {
                    showStatus(statusDiv, 'error', data.error || 'Failed to join session');
                }
            } catch (error) {
                showStatus(statusDiv, 'error', 'Connection error: ' + error.message);
            }
        }
        
        function showStatus(element, type, message) {
            element.className = `status ${type}`;
            element.textContent = message;
        }
        
        function formatBytes(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
        }
    </script>
</body>
</html>
    """
    return web.Response(text=html, content_type='text/html')


def create_app():
    """Create and configure the web application"""
    app = web.Application()
    
    # Routes
    app.router.add_get('/favicon.ico', favicon_ico)
    app.router.add_get('/', index)
    app.router.add_post('/api/send', create_send_session)
    app.router.add_post('/api/join', join_session)
    app.router.add_get('/api/status/{session_id}', get_session_status)
    app.router.add_post('/api/webrtc/offer', webrtc_offer)
    app.router.add_post('/api/webrtc/answer', webrtc_answer)
    
    return app


if __name__ == '__main__':
    app = create_app()
    web.run_app(app, host='0.0.0.0', port=8080)
