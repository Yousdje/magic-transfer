#!/usr/bin/env python3
"""
Comprehensive tests for Secure File Transfer Server

Run with: pytest test_server.py -v
"""

import asyncio
import hashlib
import hmac
import io
import json
import os
import secrets
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from aiohttp import web, FormData
from aiohttp.test_utils import AioHTTPTestCase, TestClient

# Patch directories before importing server so it doesn't try to create /input /output
_tmpdir = tempfile.mkdtemp()
_input_dir = Path(_tmpdir) / "input"
_output_dir = Path(_tmpdir) / "output"
_input_dir.mkdir()
_output_dir.mkdir()

with patch.dict(os.environ, {"LOG_FORMAT": "text"}):
    import server
    # Override directories for tests
    server.transfer.upload_dir = _input_dir
    server.transfer.download_dir = _output_dir


# ============= Fixtures =============

@pytest.fixture
def cli(event_loop, aiohttp_client):
    """Create test client for the server app"""
    app = server.create_app()
    return event_loop.run_until_complete(aiohttp_client(app))


@pytest.fixture(autouse=True)
def clean_state():
    """Reset server state between tests"""
    server.transfer.sessions.clear()
    server.transfer.websockets.clear()
    server.transfer.encryption_keys.clear()
    server.transfer.join_limiter._attempts.clear()
    server.transfer.upload_limiter._attempts.clear()
    server.transfer.upload_dir = _input_dir
    server.transfer.download_dir = _output_dir
    server.METRICS.update({
        "requests_total": 0,
        "uploads_total": 0,
        "downloads_total": 0,
        "transfers_completed": 0,
        "transfers_failed": 0,
        "bytes_uploaded": 0,
        "bytes_downloaded": 0,
    })
    yield


# ============= Unit Tests: Crypto =============

class TestCrypto:
    """Test cryptographic functions"""

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypted data should decrypt to original plaintext"""
        t = server.UniversalFileTransfer()
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"Hello, secure world!"

        ciphertext = t.encrypt_chunk(key, plaintext, nonce)
        decrypted = t.decrypt_chunk(key, ciphertext, nonce)

        assert decrypted == plaintext

    def test_encrypt_different_nonce_different_output(self):
        """Same plaintext with different nonces should produce different ciphertext"""
        t = server.UniversalFileTransfer()
        key = secrets.token_bytes(32)
        plaintext = b"same data"

        ct1 = t.encrypt_chunk(key, plaintext, secrets.token_bytes(12))
        ct2 = t.encrypt_chunk(key, plaintext, secrets.token_bytes(12))

        assert ct1 != ct2

    def test_decrypt_wrong_key_fails(self):
        """Decryption with wrong key should raise an error"""
        t = server.UniversalFileTransfer()
        key1 = secrets.token_bytes(32)
        key2 = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        plaintext = b"secret data"

        ciphertext = t.encrypt_chunk(key1, plaintext, nonce)

        with pytest.raises(Exception):
            t.decrypt_chunk(key2, ciphertext, nonce)

    def test_decrypt_wrong_nonce_fails(self):
        """Decryption with wrong nonce should raise an error"""
        t = server.UniversalFileTransfer()
        key = secrets.token_bytes(32)
        nonce1 = secrets.token_bytes(12)
        nonce2 = secrets.token_bytes(12)
        plaintext = b"secret data"

        ciphertext = t.encrypt_chunk(key, plaintext, nonce1)

        with pytest.raises(Exception):
            t.decrypt_chunk(key, ciphertext, nonce2)

    def test_key_derivation_deterministic(self):
        """Same pairing code + salt should produce same key"""
        t = server.UniversalFileTransfer()
        salt = secrets.token_bytes(16)
        code = "12345678"

        key1 = t.derive_encryption_key(code, salt)
        key2 = t.derive_encryption_key(code, salt)

        assert key1 == key2

    def test_key_derivation_different_codes(self):
        """Different pairing codes should produce different keys"""
        t = server.UniversalFileTransfer()
        salt = secrets.token_bytes(16)

        key1 = t.derive_encryption_key("12345678", salt)
        key2 = t.derive_encryption_key("87654321", salt)

        assert key1 != key2

    def test_key_derivation_different_salts(self):
        """Different salts should produce different keys"""
        t = server.UniversalFileTransfer()
        code = "12345678"

        key1 = t.derive_encryption_key(code, secrets.token_bytes(16))
        key2 = t.derive_encryption_key(code, secrets.token_bytes(16))

        assert key1 != key2

    def test_key_length_is_256_bits(self):
        """Derived key should be 32 bytes (256 bits) for AES-256"""
        t = server.UniversalFileTransfer()
        key = t.derive_encryption_key("12345678", secrets.token_bytes(16))
        assert len(key) == 32


# ============= Unit Tests: Pairing Code =============

class TestPairingCode:
    """Test pairing code generation"""

    def test_pairing_code_length(self):
        """Pairing code should be 8 digits"""
        t = server.UniversalFileTransfer()
        code = t.generate_pairing_code()
        assert len(code) == 8

    def test_pairing_code_digits_only(self):
        """Pairing code should contain only digits"""
        t = server.UniversalFileTransfer()
        for _ in range(100):
            code = t.generate_pairing_code()
            assert code.isdigit()

    def test_pairing_codes_unique(self):
        """Generated codes should be unique (statistically)"""
        t = server.UniversalFileTransfer()
        codes = {t.generate_pairing_code() for _ in range(1000)}
        # With 10^8 possibilities, 1000 codes should all be unique
        assert len(codes) == 1000


# ============= Unit Tests: Filename Sanitization =============

class TestFilenameSanitization:
    """Test path traversal prevention"""

    def test_strips_directory_traversal(self):
        assert server.UniversalFileTransfer.sanitize_filename("../../etc/passwd") == "passwd"

    def test_strips_absolute_path(self):
        assert server.UniversalFileTransfer.sanitize_filename("/etc/shadow") == "shadow"

    def test_strips_windows_path(self):
        result = server.UniversalFileTransfer.sanitize_filename("C:\\Windows\\system32\\cmd.exe")
        assert ".." not in result
        assert "\\" not in result
        assert "/" not in result

    def test_strips_null_bytes(self):
        result = server.UniversalFileTransfer.sanitize_filename("file\x00.txt")
        assert "\x00" not in result

    def test_strips_leading_dots(self):
        result = server.UniversalFileTransfer.sanitize_filename("...hidden")
        assert not result.startswith(".")

    def test_empty_filename_gets_fallback(self):
        assert server.UniversalFileTransfer.sanitize_filename("") == "unnamed_file"

    def test_only_dots_gets_fallback(self):
        assert server.UniversalFileTransfer.sanitize_filename("...") == "unnamed_file"

    def test_normal_filename_preserved(self):
        assert server.UniversalFileTransfer.sanitize_filename("photo.jpg") == "photo.jpg"

    def test_filename_with_spaces(self):
        result = server.UniversalFileTransfer.sanitize_filename("my document (1).pdf")
        assert "my document (1).pdf" == result

    def test_long_filename_truncated(self):
        long_name = "a" * 300 + ".txt"
        result = server.UniversalFileTransfer.sanitize_filename(long_name)
        assert len(result) <= 255

    def test_nested_traversal(self):
        result = server.UniversalFileTransfer.sanitize_filename("../../../../../../../tmp/evil")
        assert "/" not in result
        assert ".." not in result


# ============= Unit Tests: Rate Limiter =============

class TestRateLimiter:
    """Test rate limiting logic"""

    def test_allows_within_limit(self):
        rl = server.RateLimiter(max_attempts=3, window_seconds=60)
        assert rl.is_allowed("client1") is True
        assert rl.is_allowed("client1") is True
        assert rl.is_allowed("client1") is True

    def test_blocks_over_limit(self):
        rl = server.RateLimiter(max_attempts=3, window_seconds=60)
        rl.is_allowed("client1")
        rl.is_allowed("client1")
        rl.is_allowed("client1")
        assert rl.is_allowed("client1") is False

    def test_different_clients_independent(self):
        rl = server.RateLimiter(max_attempts=1, window_seconds=60)
        assert rl.is_allowed("client1") is True
        assert rl.is_allowed("client1") is False
        assert rl.is_allowed("client2") is True  # Different client

    def test_window_expiry(self):
        rl = server.RateLimiter(max_attempts=1, window_seconds=1)
        assert rl.is_allowed("client1") is True
        assert rl.is_allowed("client1") is False
        time.sleep(1.1)
        assert rl.is_allowed("client1") is True  # Window expired

    def test_cleanup_removes_stale(self):
        rl = server.RateLimiter(max_attempts=5, window_seconds=1)
        rl.is_allowed("client1")
        rl.is_allowed("client2")
        time.sleep(1.1)
        rl.cleanup()
        assert "client1" not in rl._attempts
        assert "client2" not in rl._attempts


# ============= Integration Tests: API Endpoints =============

class TestHealthEndpoint:

    @pytest.mark.asyncio
    async def test_health_returns_ok(self, cli):
        resp = await cli.get("/health")
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "ok"


class TestMetricsEndpoint:

    @pytest.mark.asyncio
    async def test_metrics_returns_prometheus_format(self, cli):
        resp = await cli.get("/metrics")
        assert resp.status == 200
        text = await resp.text()
        assert "secure_transfer_uptime_seconds" in text
        assert "secure_transfer_sessions_active" in text
        assert "secure_transfer_memory_rss_kb" in text


class TestUploadEndpoint:

    @pytest.mark.asyncio
    async def test_upload_file_success(self, cli):
        data = FormData()
        data.add_field("file", b"test content 12345",
                       filename="test.txt",
                       content_type="application/octet-stream")

        resp = await cli.post("/api/upload", data=data)
        assert resp.status == 200
        result = await resp.json()
        assert "pairing_code" in result
        assert len(result["pairing_code"]) == 8
        assert result["file_name"] == "test.txt"
        assert result["file_size"] == 18

    @pytest.mark.asyncio
    async def test_upload_no_file_returns_400(self, cli):
        data = FormData()
        data.add_field("other_field", b"not a file")

        resp = await cli.post("/api/upload", data=data)
        assert resp.status == 400

    @pytest.mark.asyncio
    async def test_upload_sanitizes_filename(self, cli):
        data = FormData()
        data.add_field("file", b"evil content",
                       filename="../../etc/passwd",
                       content_type="application/octet-stream")

        resp = await cli.post("/api/upload", data=data)
        assert resp.status == 200
        result = await resp.json()
        assert "/" not in result["file_name"]
        assert ".." not in result["file_name"]


class TestCreateSendSession:

    @pytest.mark.asyncio
    async def test_create_session_success(self, cli):
        resp = await cli.post("/api/send", json={
            "filename": "document.pdf",
            "file_size": 1024
        })
        assert resp.status == 200
        result = await resp.json()
        assert len(result["pairing_code"]) == 8

    @pytest.mark.asyncio
    async def test_create_session_missing_fields(self, cli):
        resp = await cli.post("/api/send", json={"filename": "test.txt"})
        assert resp.status == 400

    @pytest.mark.asyncio
    async def test_create_session_invalid_size(self, cli):
        resp = await cli.post("/api/send", json={
            "filename": "test.txt",
            "file_size": -1
        })
        assert resp.status == 400

    @pytest.mark.asyncio
    async def test_session_limit_enforced(self, cli):
        """Should reject when MAX_SESSIONS is reached"""
        original = server.UniversalFileTransfer.MAX_SESSIONS
        server.UniversalFileTransfer.MAX_SESSIONS = 2
        try:
            resp1 = await cli.post("/api/send", json={"filename": "a.txt", "file_size": 1})
            assert resp1.status == 200
            resp2 = await cli.post("/api/send", json={"filename": "b.txt", "file_size": 1})
            assert resp2.status == 200
            resp3 = await cli.post("/api/send", json={"filename": "c.txt", "file_size": 1})
            assert resp3.status == 429
        finally:
            server.UniversalFileTransfer.MAX_SESSIONS = original


class TestJoinEndpoint:

    @pytest.mark.asyncio
    async def test_join_valid_code(self, cli):
        # Create session first
        send_resp = await cli.post("/api/send", json={
            "filename": "test.txt", "file_size": 100
        })
        send_data = await send_resp.json()
        code = send_data["pairing_code"]

        # Join with code
        join_resp = await cli.post("/api/join", json={"pairing_code": code})
        assert join_resp.status == 200
        join_data = await join_resp.json()
        assert join_data["file_name"] == "test.txt"

    @pytest.mark.asyncio
    async def test_join_invalid_code(self, cli):
        resp = await cli.post("/api/join", json={"pairing_code": "00000000"})
        assert resp.status == 404

    @pytest.mark.asyncio
    async def test_join_wrong_length_code(self, cli):
        resp = await cli.post("/api/join", json={"pairing_code": "123"})
        assert resp.status == 400

    @pytest.mark.asyncio
    async def test_join_non_digit_code(self, cli):
        resp = await cli.post("/api/join", json={"pairing_code": "abcdefgh"})
        assert resp.status == 400

    @pytest.mark.asyncio
    async def test_join_rate_limiting(self, cli):
        """Should rate limit after too many failed attempts"""
        for i in range(5):
            await cli.post("/api/join", json={"pairing_code": f"{i:08d}"})

        # 6th attempt should be rate limited
        resp = await cli.post("/api/join", json={"pairing_code": "99999999"})
        assert resp.status == 429
        data = await resp.json()
        assert "Too many" in data["error"]

    @pytest.mark.asyncio
    async def test_join_doesnt_reuse_paired_session(self, cli):
        """Once a session is paired, the code shouldn't work again"""
        send_resp = await cli.post("/api/send", json={
            "filename": "test.txt", "file_size": 100
        })
        code = (await send_resp.json())["pairing_code"]

        # First join succeeds
        join1 = await cli.post("/api/join", json={"pairing_code": code})
        assert join1.status == 200

        # Second join with same code should fail (session now 'paired', not 'waiting')
        join2 = await cli.post("/api/join", json={"pairing_code": code})
        assert join2.status == 404


class TestSessionEndpoint:

    @pytest.mark.asyncio
    async def test_get_session_strips_sensitive_data(self, cli):
        send_resp = await cli.post("/api/send", json={
            "filename": "test.txt", "file_size": 100
        })
        session_id = (await send_resp.json())["session_id"]

        resp = await cli.get(f"/api/session/{session_id}")
        assert resp.status == 200
        data = await resp.json()
        # Sensitive fields must be stripped
        assert "pairing_code" not in data
        assert "file_path" not in data

    @pytest.mark.asyncio
    async def test_get_nonexistent_session(self, cli):
        resp = await cli.get("/api/session/nonexistent")
        assert resp.status == 404


# ============= Integration Tests: Full Transfer Flow =============

class TestFullTransfer:

    @pytest.mark.asyncio
    async def test_upload_join_download_complete(self, cli):
        """End-to-end: upload file, join, download, verify"""
        test_content = b"This is a test file for secure transfer!" * 100

        # 1. Upload file
        data = FormData()
        data.add_field("file", test_content,
                       filename="transfer_test.bin",
                       content_type="application/octet-stream")
        upload_resp = await cli.post("/api/upload", data=data)
        assert upload_resp.status == 200
        upload_data = await upload_resp.json()

        # 2. Join session
        join_resp = await cli.post("/api/join", json={
            "pairing_code": upload_data["pairing_code"]
        })
        assert join_resp.status == 200
        join_data = await join_resp.json()
        assert join_data["file_name"] == "transfer_test.bin"

        # 3. Download (encrypted stream)
        dl_resp = await cli.get(f"/api/download/{join_data['sender_session_id']}")
        assert dl_resp.status == 200


class TestWebUI:

    @pytest.mark.asyncio
    async def test_index_returns_html(self, cli):
        resp = await cli.get("/")
        assert resp.status == 200
        assert "text/html" in resp.headers["Content-Type"]
        text = await resp.text()
        assert "Secure Transfer" in text

    @pytest.mark.asyncio
    async def test_manifest_json(self, cli):
        resp = await cli.get("/manifest.json")
        assert resp.status == 200
        data = await resp.json()
        assert data["name"] == "Secure Transfer"

    @pytest.mark.asyncio
    async def test_service_worker(self, cli):
        resp = await cli.get("/sw.js")
        assert resp.status == 200
        assert "javascript" in resp.headers["Content-Type"]


# ============= Security Tests =============

class TestSecurityPathTraversal:
    """Verify path traversal attacks are blocked"""

    @pytest.mark.asyncio
    async def test_upload_traversal_filename(self, cli):
        for evil_name in [
            "../../etc/passwd",
            "../../../root/.ssh/id_rsa",
            "..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            ".\\.\\.\\.\\evil.txt",
            "\x00evil.txt",
        ]:
            data = FormData()
            data.add_field("file", b"test",
                           filename=evil_name,
                           content_type="application/octet-stream")
            resp = await cli.post("/api/upload", data=data)
            assert resp.status == 200
            result = await resp.json()
            # Filename should never contain path separators or traversal
            assert "/" not in result["file_name"]
            assert "\\" not in result["file_name"]
            assert ".." not in result["file_name"]
            assert "\x00" not in result["file_name"]


class TestSecurityTimingSafe:
    """Verify timing-safe comparison is used"""

    def test_join_uses_hmac_compare(self):
        """The join_session method should use hmac.compare_digest"""
        import inspect
        source = inspect.getsource(server.UniversalFileTransfer.join_session)
        assert "hmac.compare_digest" in source
        # Should NOT use plain == for pairing code
        assert "== pairing_code" not in source


class TestSecurityErrorLeaks:
    """Verify internal errors are not leaked"""

    @pytest.mark.asyncio
    async def test_upload_error_doesnt_leak_internals(self, cli):
        # Send malformed multipart
        resp = await cli.post("/api/upload", data=b"not multipart",
                              headers={"Content-Type": "multipart/form-data; boundary=invalid"})
        # Should get generic error, not stack trace
        if resp.status == 500:
            data = await resp.json()
            assert "Traceback" not in data.get("error", "")
            assert "/home/" not in data.get("error", "")

    @pytest.mark.asyncio
    async def test_send_error_doesnt_leak_internals(self, cli):
        resp = await cli.post("/api/send", data=b"not json",
                              headers={"Content-Type": "application/json"})
        if resp.status == 500:
            data = await resp.json()
            assert "Traceback" not in data.get("error", "")


class TestSecuritySessionLimits:
    """Verify session limits prevent DoS"""

    @pytest.mark.asyncio
    async def test_max_sessions_enforced(self, cli):
        original = server.UniversalFileTransfer.MAX_SESSIONS
        server.UniversalFileTransfer.MAX_SESSIONS = 3
        try:
            for i in range(3):
                resp = await cli.post("/api/send", json={
                    "filename": f"file{i}.txt", "file_size": 1
                })
                assert resp.status == 200

            # Session 4 should be rejected
            resp = await cli.post("/api/send", json={
                "filename": "overflow.txt", "file_size": 1
            })
            assert resp.status == 429
        finally:
            server.UniversalFileTransfer.MAX_SESSIONS = original
