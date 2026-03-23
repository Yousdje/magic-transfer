#!/usr/bin/env python3
"""
Secure File Transfer - CLI Version
Command-line interface for direct P2P transfers
"""

import sys
import asyncio
import argparse
import secrets
import hashlib
import base64
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import socket
import json


class SecureCLITransfer:
    """CLI-based secure file transfer"""
    
    def __init__(self):
        self.chunk_size = 65536  # 64KB chunks for network
        
    def generate_pairing_code(self) -> str:
        """Generate secure 8-digit pairing code (~26.5 bits entropy)"""
        return ''.join(secrets.choice('0123456789') for _ in range(8))

    def derive_key(self, pairing_code: str, salt: bytes) -> bytes:
        """Derive AES-256 key from pairing code"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        return kdf.derive(pairing_code.encode())
    
    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    async def send_file(self, file_path: str, host: str = '0.0.0.0', port: int = 9999):
        """Send file as server"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            print(f"❌ Bestand niet gevonden: {file_path}")
            return
        
        # Generate pairing code and salt
        pairing_code = self.generate_pairing_code()
        salt = secrets.token_bytes(16)
        encryption_key = self.derive_key(pairing_code, salt)
        
        # Calculate file metadata
        file_size = file_path.stat().st_size
        file_hash = self.calculate_file_hash(str(file_path))
        
        print("🔐 Secure File Transfer - SENDER")
        print("=" * 50)
        print(f"📁 Bestand: {file_path.name}")
        print(f"📊 Grootte: {self._format_bytes(file_size)}")
        print(f"🔒 Hash: {file_hash[:16]}...")
        print(f"📡 Listening on: {host}:{port}")
        print("=" * 50)
        print(f"\n🔑 PAIRING CODE: {pairing_code}")
        print("\n⚠️  Deel deze code met de ontvanger!")
        print("⏳ Wachten op verbinding...\n")
        
        # Start server
        server = await asyncio.start_server(
            lambda r, w: self._handle_sender_client(
                r, w, file_path, encryption_key, salt, file_hash, file_size
            ),
            host, port
        )
        
        async with server:
            await server.serve_forever()
    
    async def _handle_sender_client(self, reader, writer, file_path, encryption_key, 
                                    salt, file_hash, file_size):
        """Handle sender client connection"""
        try:
            addr = writer.get_extra_info('peername')
            print(f"✅ Verbinding van: {addr[0]}:{addr[1]}")
            
            # Send metadata
            metadata = {
                'filename': file_path.name,
                'size': file_size,
                'hash': file_hash,
                'salt': base64.b64encode(salt).decode()
            }
            
            writer.write(json.dumps(metadata).encode() + b'\n')
            await writer.drain()
            
            # Wait for ready signal
            ready = await reader.readline()
            if ready.decode().strip() != 'READY':
                print("❌ Client niet ready")
                return
            
            print("📤 Starten met versturen...")
            
            # Send encrypted chunks
            aesgcm = AESGCM(encryption_key)
            chunk_num = 0
            
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    # Encrypt chunk
                    nonce = secrets.token_bytes(12)
                    encrypted = aesgcm.encrypt(nonce, chunk, None)
                    
                    # Send: nonce_length(4) + nonce + data_length(4) + data
                    writer.write(len(nonce).to_bytes(4, 'big'))
                    writer.write(nonce)
                    writer.write(len(encrypted).to_bytes(4, 'big'))
                    writer.write(encrypted)
                    await writer.drain()
                    
                    chunk_num += 1
                    progress = (chunk_num * self.chunk_size / file_size) * 100
                    print(f"\r📊 Progress: {min(progress, 100):.1f}%", end='', flush=True)
            
            # Send completion marker
            writer.write(b'\x00\x00\x00\x00')
            await writer.drain()
            
            print("\n\n✅ Transfer compleet!")
            print("🔐 Wachten op verificatie...")
            
            # Wait for verification
            verification = await reader.readline()
            result = json.loads(verification.decode())
            
            if result['status'] == 'success':
                print("✅ Bestand succesvol geverifieerd door ontvanger!")
            else:
                print(f"❌ Verificatie gefaald: {result.get('error')}")
            
        except Exception as e:
            print(f"\n❌ Fout tijdens verzenden: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def receive_file(self, pairing_code: str, output_dir: str = '.', 
                          host: str = 'localhost', port: int = 9999):
        """Receive file as client"""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        print("🔐 Secure File Transfer - RECEIVER")
        print("=" * 50)
        print(f"🔑 Pairing Code: {pairing_code}")
        print(f"📡 Verbinden met: {host}:{port}")
        print("=" * 50)
        
        try:
            # Connect to sender
            reader, writer = await asyncio.open_connection(host, port)
            print("✅ Verbonden met sender")
            
            # Receive metadata
            metadata_line = await reader.readline()
            metadata = json.loads(metadata_line.decode())
            
            filename = Path(metadata['filename']).name.replace('\x00', '')
            if not filename or filename.startswith('.'):
                filename = 'received_file'
            file_size = metadata['size']
            expected_hash = metadata['hash']
            salt = base64.b64decode(metadata['salt'])
            
            print(f"\n📁 Bestand: {filename}")
            print(f"📊 Grootte: {self._format_bytes(file_size)}")
            print(f"🔒 Expected hash: {expected_hash[:16]}...")
            
            # Derive encryption key
            encryption_key = self.derive_key(pairing_code, salt)
            
            # Send ready signal
            writer.write(b'READY\n')
            await writer.drain()
            
            print("\n📥 Ontvangen...")
            
            # Receive and decrypt chunks
            output_path = output_dir / filename
            aesgcm = AESGCM(encryption_key)
            received_bytes = 0
            
            with open(output_path, 'wb') as f:
                while True:
                    # Read nonce length
                    nonce_len_bytes = await reader.readexactly(4)
                    nonce_len = int.from_bytes(nonce_len_bytes, 'big')
                    
                    if nonce_len == 0:  # Completion marker
                        break
                    
                    # Read nonce
                    nonce = await reader.readexactly(nonce_len)
                    
                    # Read data length
                    data_len_bytes = await reader.readexactly(4)
                    data_len = int.from_bytes(data_len_bytes, 'big')
                    
                    # Read encrypted data
                    encrypted = await reader.readexactly(data_len)
                    
                    # Decrypt and write
                    plaintext = aesgcm.decrypt(nonce, encrypted, None)
                    f.write(plaintext)
                    
                    received_bytes += len(plaintext)
                    progress = (received_bytes / file_size) * 100
                    print(f"\r📊 Progress: {progress:.1f}%", end='', flush=True)
            
            print("\n\n🔐 Verificatie...")
            
            # Verify file hash
            received_hash = self.calculate_file_hash(str(output_path))
            
            if received_hash == expected_hash:
                print("✅ Hash verificatie geslaagd!")
                print(f"📁 Opgeslagen in: {output_path}")
                verification = {'status': 'success'}
            else:
                print("❌ Hash verificatie gefaald!")
                print(f"   Expected: {expected_hash}")
                print(f"   Received: {received_hash}")
                verification = {'status': 'error', 'error': 'hash_mismatch'}
            
            # Send verification result
            writer.write((json.dumps(verification) + '\n').encode())
            await writer.drain()
            
        except Exception as e:
            print(f"\n❌ Fout tijdens ontvangen: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    def _format_bytes(self, bytes_num):
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_num < 1024.0:
                return f"{bytes_num:.2f} {unit}"
            bytes_num /= 1024.0


async def main():
    parser = argparse.ArgumentParser(
        description='Secure P2P File Transfer CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Send file (start server)
  %(prog)s send /path/to/file.txt
  %(prog)s send /path/to/file.txt --port 9999
  
  # Receive file (connect to server)
  %(prog)s receive 123456 --host 192.168.1.100
  %(prog)s receive 123456 --host 192.168.1.100 --output /downloads
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Send command
    send_parser = subparsers.add_parser('send', help='Send a file')
    send_parser.add_argument('file', help='Path to file to send')
    send_parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    send_parser.add_argument('--port', type=int, default=9999, help='Port to bind to (default: 9999)')
    
    # Receive command
    recv_parser = subparsers.add_parser('receive', help='Receive a file')
    recv_parser.add_argument('code', help='6-digit pairing code')
    recv_parser.add_argument('--host', default='localhost', help='Host to connect to')
    recv_parser.add_argument('--port', type=int, default=9999, help='Port to connect to (default: 9999)')
    recv_parser.add_argument('--output', default='.', help='Output directory (default: current)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    transfer = SecureCLITransfer()
    
    if args.command == 'send':
        await transfer.send_file(args.file, args.host, args.port)
    elif args.command == 'receive':
        if len(args.code) != 8 or not args.code.isdigit():
            print("❌ Pairing code moet 8 cijfers zijn")
            return
        await transfer.receive_file(args.code, args.output, args.host, args.port)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Transfer geannuleerd door gebruiker")
    except Exception as e:
        print(f"\n❌ Onverwachte fout: {e}")
        sys.exit(1)
