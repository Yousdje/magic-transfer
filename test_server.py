"""
Tests for MagicTransfer zero-knowledge server.

The server never sees plaintext — it stores and returns encrypted blobs.
We use dummy encrypted data since actual crypto happens in the browser.

Run with: pytest test_server.py -v
"""

import io
import pytest
import secrets
import os

os.makedirs("/output/uploads", exist_ok=True)

from aiohttp import FormData
from server import create_app, store


@pytest.fixture
def app():
    return create_app()


@pytest.fixture
async def client(aiohttp_client, app):
    return await aiohttp_client(app)


def make_auth_token():
    return secrets.token_hex(32)


def make_encrypted_meta():
    return secrets.token_urlsafe(64)


async def upload_test_file(client, data=b"encrypted-test-data", auth_token=None, meta=None):
    if auth_token is None:
        auth_token = make_auth_token()
    if meta is None:
        meta = make_encrypted_meta()

    fd = FormData()
    fd.add_field('blob', io.BytesIO(data), filename='encrypted.bin',
                 content_type='application/octet-stream')
    fd.add_field('meta', meta)
    fd.add_field('auth_token', auth_token)

    resp = await client.post('/api/upload', data=fd)
    result = await resp.json()
    return resp, result, auth_token, meta


# ============= Health =============

@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get('/health')
    assert resp.status == 200
    data = await resp.json()
    assert data['status'] == 'ok'


# ============= Upload =============

@pytest.mark.asyncio
async def test_upload_success(client):
    resp, result, _, _ = await upload_test_file(client)
    assert resp.status == 200
    assert 'file_id' in result


@pytest.mark.asyncio
async def test_upload_missing_fields(client):
    fd = FormData()
    fd.add_field('blob', io.BytesIO(b"data"), filename='test.bin')
    resp = await client.post('/api/upload', data=fd)
    assert resp.status == 400


@pytest.mark.asyncio
async def test_upload_invalid_auth_token(client):
    fd = FormData()
    fd.add_field('blob', io.BytesIO(b"data"), filename='test.bin')
    fd.add_field('meta', make_encrypted_meta())
    fd.add_field('auth_token', 'tooshort')
    resp = await client.post('/api/upload', data=fd)
    assert resp.status == 400


@pytest.mark.asyncio
async def test_upload_size_limit(client):
    import server
    old_limit = server.MAX_UPLOAD_BYTES
    server.MAX_UPLOAD_BYTES = 100
    try:
        fd = FormData()
        fd.add_field('blob', io.BytesIO(b"x" * 200), filename='big.bin')
        fd.add_field('meta', make_encrypted_meta())
        fd.add_field('auth_token', make_auth_token())
        resp = await client.post('/api/upload', data=fd)
        assert resp.status == 413
    finally:
        server.MAX_UPLOAD_BYTES = old_limit


# ============= Download =============

@pytest.mark.asyncio
async def test_download_valid_auth(client):
    test_data = b"encrypted-blob-content"
    resp, result, auth_token, _ = await upload_test_file(client, data=test_data)
    file_id = result['file_id']

    resp = await client.get(f'/api/download/{file_id}',
                            headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status == 200
    body = await resp.read()
    assert body == test_data


@pytest.mark.asyncio
async def test_download_invalid_auth(client):
    resp, result, _, _ = await upload_test_file(client)
    resp = await client.get(f'/api/download/{result["file_id"]}',
                            headers={'Authorization': f'Bearer {make_auth_token()}'})
    assert resp.status == 401


@pytest.mark.asyncio
async def test_download_no_auth(client):
    resp, result, _, _ = await upload_test_file(client)
    resp = await client.get(f'/api/download/{result["file_id"]}')
    assert resp.status == 401


@pytest.mark.asyncio
async def test_download_nonexistent(client):
    resp = await client.get('/api/download/nonexistent',
                            headers={'Authorization': f'Bearer {make_auth_token()}'})
    assert resp.status == 401


# ============= Info =============

@pytest.mark.asyncio
async def test_info_valid_auth(client):
    resp, result, auth_token, meta = await upload_test_file(client)
    resp = await client.get(f'/api/info/{result["file_id"]}',
                            headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status == 200
    data = await resp.json()
    assert data['content_type'] == 'file'
    assert data['encrypted_meta'] == meta
    assert data['status'] == 'active'


@pytest.mark.asyncio
async def test_info_invalid_auth(client):
    resp, result, _, _ = await upload_test_file(client)
    resp = await client.get(f'/api/info/{result["file_id"]}',
                            headers={'Authorization': f'Bearer {make_auth_token()}'})
    assert resp.status == 401


# ============= Burn After Read =============

@pytest.mark.asyncio
async def test_burn_after_read_file(client):
    resp, result, auth_token, _ = await upload_test_file(client)
    file_id = result['file_id']

    # Download
    resp = await client.get(f'/api/download/{file_id}',
                            headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status == 200

    # Complete (burn)
    resp = await client.post(f'/api/complete/{file_id}',
                             headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status == 200

    # Second download fails
    resp = await client.get(f'/api/download/{file_id}',
                            headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status in (401, 404, 410)


@pytest.mark.asyncio
async def test_complete_invalid_auth(client):
    resp, result, _, _ = await upload_test_file(client)
    resp = await client.post(f'/api/complete/{result["file_id"]}',
                             headers={'Authorization': f'Bearer {make_auth_token()}'})
    assert resp.status == 401


# ============= Text =============

@pytest.mark.asyncio
async def test_text_share(client):
    auth_token = make_auth_token()
    encrypted_text = secrets.token_urlsafe(100)
    meta = make_encrypted_meta()

    resp = await client.post('/api/text', json={
        'encrypted_text': encrypted_text, 'meta': meta, 'auth_token': auth_token})
    assert resp.status == 200
    file_id = (await resp.json())['file_id']

    resp = await client.get(f'/api/text/{file_id}',
                            headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status == 200
    data = await resp.json()
    assert data['encrypted_text'] == encrypted_text


@pytest.mark.asyncio
async def test_text_burn_after_read(client):
    auth_token = make_auth_token()
    resp = await client.post('/api/text', json={
        'encrypted_text': secrets.token_urlsafe(50),
        'meta': make_encrypted_meta(), 'auth_token': auth_token})
    file_id = (await resp.json())['file_id']

    resp = await client.get(f'/api/text/{file_id}',
                            headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status == 200

    resp = await client.post(f'/api/complete/{file_id}',
                             headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status == 200

    resp = await client.get(f'/api/text/{file_id}',
                            headers={'Authorization': f'Bearer {auth_token}'})
    assert resp.status in (401, 404, 410)


@pytest.mark.asyncio
async def test_text_invalid_auth(client):
    auth_token = make_auth_token()
    resp = await client.post('/api/text', json={
        'encrypted_text': secrets.token_urlsafe(50),
        'meta': make_encrypted_meta(), 'auth_token': auth_token})
    file_id = (await resp.json())['file_id']

    resp = await client.get(f'/api/text/{file_id}',
                            headers={'Authorization': f'Bearer {make_auth_token()}'})
    assert resp.status == 401


@pytest.mark.asyncio
async def test_text_missing_fields(client):
    resp = await client.post('/api/text', json={'encrypted_text': 'data'})
    assert resp.status == 400


# ============= Pages =============

@pytest.mark.asyncio
async def test_index_page(client):
    resp = await client.get('/')
    assert resp.status == 200
    text = await resp.text()
    assert 'MagicTransfer' in text
    assert 'Zero-knowledge' in text


@pytest.mark.asyncio
async def test_download_page(client):
    resp = await client.get('/d/somefile')
    assert resp.status == 200
    text = await resp.text()
    assert 'MagicTransfer' in text
    assert 'Decrypting' in text


# ============= Headers =============

@pytest.mark.asyncio
async def test_csp_header(client):
    resp = await client.get('/')
    csp = resp.headers.get('Content-Security-Policy', '')
    assert "script-src 'nonce-" in csp
    assert "frame-ancestors 'none'" in csp


@pytest.mark.asyncio
async def test_security_headers(client):
    resp = await client.get('/')
    assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
    assert resp.headers.get('X-Frame-Options') == 'DENY'
    assert resp.headers.get('Referrer-Policy') == 'no-referrer'


# ============= Metrics =============

@pytest.mark.asyncio
async def test_metrics(client):
    resp = await client.get('/metrics')
    assert resp.status == 200
    text = await resp.text()
    assert 'magictransfer_uploads_total' in text


# ============= Session Expiry =============

@pytest.mark.asyncio
async def test_session_expiry(client):
    resp, result, _, _ = await upload_test_file(client)
    file_id = result['file_id']

    from datetime import datetime, timedelta
    store.sessions[file_id]['created_at'] = (datetime.now() - timedelta(hours=2)).isoformat()
    store.cleanup_expired()
    assert file_id not in store.sessions
