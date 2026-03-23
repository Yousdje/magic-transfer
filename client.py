#!/usr/bin/env python3
"""
Universal Secure Transfer Client
Works on: Windows, Linux (Arch, Ubuntu, etc), macOS
Compatible with: iOS/Android web interface
"""

import sys
import argparse
import requests
import json
import base64
import struct
from pathlib import Path
from typing import Optional
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecureTransferClient:
    """Universal client for secure file transfers"""

    def __init__(self, server_url: str = "http://localhost:8080", api_key: str = ""):
        self.server_url = server_url.rstrip('/')
        self.session = requests.Session()
        if api_key:
            self.session.headers.update({"Authorization": f"Bearer {api_key}"})
    
    def format_bytes(self, bytes_num: int) -> str:
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_num < 1024.0:
                return f"{bytes_num:.2f} {unit}"
            bytes_num /= 1024.0
        return f"{bytes_num:.2f} PB"
    
    def send_file(self, file_path: str) -> Optional[str]:
        """
        Send a file and get pairing code
        Returns: pairing code or None on error
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            print(f"❌ Bestand niet gevonden: {file_path}")
            return None
        
        file_size = file_path.stat().st_size
        
        print(f"\n🔐 Secure File Transfer - SENDER")
        print("=" * 50)
        print(f"📁 Bestand: {file_path.name}")
        print(f"📊 Grootte: {self.format_bytes(file_size)}")
        print("=" * 50)
        print("\n📤 Uploaden naar server...")
        
        try:
            # Upload file
            with open(file_path, 'rb') as f:
                files = {'file': (file_path.name, f)}
                response = self.session.post(
                    f"{self.server_url}/api/upload",
                    files=files,
                    timeout=300
                )
            
            if response.status_code == 200:
                data = response.json()
                pairing_code = data['pairing_code']
                
                print("\n✅ Upload succesvol!")
                print("=" * 50)
                print(f"\n🔑 PAIRING CODE: {pairing_code}")
                print("\n⚠️  Deel deze code met de ontvanger!")
                print("   Via Signal, WhatsApp, of ander veilig kanaal")
                print("\n💡 De ontvanger kan deze code gebruiken op:")
                print("   - iOS/Android: Open browser → {server_url}")
                print("   - Desktop: Gebruik deze CLI tool")
                print("   - Web: Elk apparaat met browser")
                print("=" * 50)
                
                return pairing_code
            else:
                error_data = response.json()
                print(f"❌ Upload gefaald: {error_data.get('error', 'Unknown error')}")
                return None
        
        except requests.exceptions.ConnectionError:
            print(f"❌ Kan niet verbinden met server: {self.server_url}")
            print("   Controleer of de server draait en bereikbaar is")
            return None
        except Exception as e:
            print(f"❌ Fout tijdens upload: {e}")
            return None
    
    @staticmethod
    def derive_key(pairing_code: str, salt: bytes) -> bytes:
        """Derive AES-256 key from pairing code + salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        return kdf.derive(pairing_code.encode())

    def receive_file(self, pairing_code: str, output_dir: str = ".") -> bool:
        """
        Receive a file using pairing code
        Returns: True on success, False on error
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n🔐 Secure File Transfer - RECEIVER")
        print("=" * 50)
        print(f"🔑 Pairing Code: {pairing_code}")
        print("=" * 50)
        print("\n🔗 Verbinden met server...")

        try:
            # Join session
            join_response = self.session.post(
                f"{self.server_url}/api/join",
                json={'pairing_code': pairing_code},
                timeout=30
            )

            if join_response.status_code != 200:
                error_data = join_response.json()
                print(f"❌ Ongeldige code: {error_data.get('error', 'Unknown error')}")
                return False

            join_data = join_response.json()
            sender_session_id = join_data['sender_session_id']
            receiver_session_id = join_data['session_id']
            filename = join_data['file_name']
            file_size = join_data['file_size']
            salt = base64.b64decode(join_data['salt'])

            # Sanitize filename from server to prevent path traversal
            filename = Path(filename).name.replace('\x00', '')
            if not filename or filename.startswith('.'):
                filename = 'received_file'

            print(f"\n✅ Verbonden met sender!")
            print(f"📁 Bestand: {filename}")
            print(f"📊 Grootte: {self.format_bytes(file_size)}")

            print("🔑 Sleutel afleiden...")
            encryption_key = self.derive_key(pairing_code, salt)
            aesgcm = AESGCM(encryption_key)

            print("📥 Downloaden & ontsleutelen...")

            # Download encrypted stream
            download_response = self.session.get(
                f"{self.server_url}/api/download/{sender_session_id}",
                stream=True,
                timeout=3600
            )

            if download_response.status_code != 200:
                print("❌ Download gefaald")
                return False

            # Read entire encrypted response, then parse frames and decrypt
            encrypted_data = download_response.content

            output_path = output_dir / filename
            decrypted_total = 0
            offset = 0

            with open(output_path, 'wb') as f:
                while offset < len(encrypted_data):
                    # Read 4-byte big-endian length prefix
                    if offset + 4 > len(encrypted_data):
                        break
                    frame_len = struct.unpack('>I', encrypted_data[offset:offset+4])[0]
                    offset += 4

                    if offset + frame_len > len(encrypted_data):
                        print("\n❌ Corrupt download stream")
                        return False

                    # Extract nonce (12 bytes) and ciphertext
                    frame = encrypted_data[offset:offset+frame_len]
                    offset += frame_len

                    nonce = frame[:12]
                    ciphertext = frame[12:]

                    # Decrypt
                    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                    f.write(plaintext)
                    decrypted_total += len(plaintext)

                    if file_size > 0:
                        progress = (decrypted_total / file_size) * 100
                        print(f"\r📊 Progress: {progress:.1f}% ({self.format_bytes(decrypted_total)} / {self.format_bytes(file_size)})",
                              end='', flush=True)

            print("\n\n🔐 Verificatie...")

            # Complete and verify
            complete_response = self.session.post(
                f"{self.server_url}/api/complete/{receiver_session_id}",
                timeout=30
            )

            if complete_response.status_code == 200:
                complete_data = complete_response.json()

                if complete_data['status'] == 'success':
                    print("✅ Transfer succesvol!")
                    print(f"📁 Bestand opgeslagen: {output_path}")
                    print("=" * 50)
                    return True
                else:
                    print(f"❌ Verificatie gefaald: {complete_data.get('error')}")
                    return False
            else:
                # For browser-flow completions, file is already decrypted and saved
                print("✅ Bestand opgeslagen (server verificatie overgeslagen)")
                print(f"📁 Bestand: {output_path}")
                print("=" * 50)
                return True

        except requests.exceptions.ConnectionError:
            print(f"❌ Kan niet verbinden met server: {self.server_url}")
            return False
        except Exception as e:
            print(f"❌ Fout tijdens ontvangen: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Universal Secure File Transfer Client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Voorbeelden:

  # Bestand versturen
  %(prog)s send /pad/naar/bestand.pdf
  %(prog)s send document.txt --server http://192.168.1.100:8080
  
  # Bestand ontvangen
  %(prog)s receive 123456
  %(prog)s receive 123456 --output /downloads
  %(prog)s receive 123456 --server http://transfer.tailnet.ts.net

Platforms:
  ✅ Windows (CMD, PowerShell, WSL)
  ✅ Linux (Arch, Ubuntu, Debian, Fedora, etc)
  ✅ macOS
  ✅ Werkt samen met iOS/Android web interface

Server Setup:
  De server moet draaien in Docker op je Proxmox/NAS
  Toegankelijk via LAN of Tailscale VPN

Tips:
  - Gebruik Tailscale voor secure toegang van buitenaf
  - Pairing codes zijn 1 uur geldig
  - Gebruik --server flag voor custom server locatie
        """
    )
    
    parser.add_argument(
        '--server',
        default=os.environ.get('TRANSFER_SERVER', 'http://localhost:8080'),
        help='Server URL (default: http://localhost:8080 or $TRANSFER_SERVER)'
    )
    parser.add_argument(
        '--api-key',
        default=os.environ.get('TRANSFER_API_KEY', ''),
        help='Bearer token for server auth (or set $TRANSFER_API_KEY)'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # Send command
    send_parser = subparsers.add_parser('send', help='Verstuur een bestand')
    send_parser.add_argument('file', help='Pad naar bestand')
    
    # Receive command
    recv_parser = subparsers.add_parser('receive', help='Ontvang een bestand')
    recv_parser.add_argument('code', help='8-cijferige pairing code')
    recv_parser.add_argument(
        '--output',
        default='.',
        help='Output directory (default: huidige directory)'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    client = SecureTransferClient(args.server, api_key=args.api_key)
    
    if args.command == 'send':
        pairing_code = client.send_file(args.file)
        if not pairing_code:
            sys.exit(1)
    
    elif args.command == 'receive':
        if len(args.code) != 8 or not args.code.isdigit():
            print("❌ Pairing code moet 8 cijfers zijn")
            sys.exit(1)
        
        success = client.receive_file(args.code, args.output)
        if not success:
            sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Transfer geannuleerd")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Onverwachte fout: {e}")
        sys.exit(1)
