"""JWKS cache: expiry, stale-if-error, size limit, remembered 4xx errors, key objects."""
import logging
import time

import pytest

from cognitojwt import JWKSError, constants, jwt_async, jwt_sync

from .conftest import REGION, USERPOOL_ID, jwks_for, make_key

_run = __import__('asyncio').run


@pytest.fixture(params=['sync', 'async'])
def api(request):
    if request.param == 'sync':
        return jwt_sync.decode, jwt_sync.get_public_key, jwt_sync.get_keys
    return (
        lambda *a, **kw: _run(jwt_async.decode_async(*a, **kw)),
        lambda *a: _run(jwt_async.get_public_key_async(*a)),
        jwt_async.get_keys_async,
    )


def test_key_object_is_reused(api, jwks_server, make_token):
    _, get_public_key, _ = api
    first = get_public_key(make_token(), REGION, USERPOOL_ID)
    assert get_public_key(make_token(), REGION, USERPOOL_ID) is first


def test_expired_jwks_is_downloaded_again(api, jwks_server, make_token, monkeypatch):
    decode, get_public_key, _ = api
    decode(make_token(), REGION, USERPOOL_ID)
    first = get_public_key(make_token(), REGION, USERPOOL_ID)
    monkeypatch.setattr(constants, 'KEYS_MAX_AGE', 0)
    decode(make_token(), REGION, USERPOOL_ID)
    assert jwks_server.requests == 2
    # Key objects are rebuilt for a new JWKS.
    assert get_public_key(make_token(), REGION, USERPOOL_ID) is not first


def test_removed_key_stops_being_trusted(api, jwks_server, make_token, monkeypatch):
    decode, _, _ = api
    token = make_token()
    decode(token, REGION, USERPOOL_ID)
    jwks_server.jwks = jwks_for(make_key('replacement'))
    # Still trusted while the cached JWKS is fresh...
    assert decode(token, REGION, USERPOOL_ID)['sub'] == 'user-sub'
    # ...but not once it expired and was downloaded again.
    monkeypatch.setattr(constants, 'KEYS_MAX_AGE', 0)
    with pytest.raises(Exception, match='Public key not found'):
        decode(token, REGION, USERPOOL_ID)


def test_stale_keys_are_used_when_refresh_fails(api, jwks_server, make_token, monkeypatch, caplog):
    decode, _, _ = api
    decode(make_token(), REGION, USERPOOL_ID)
    monkeypatch.setattr(constants, 'KEYS_MAX_AGE', 0)
    monkeypatch.setattr(constants, 'KEYS_REFRESH_INTERVAL', 0.3)
    jwks_server.status = 500
    with caplog.at_level(logging.WARNING, logger='cognitojwt'):
        assert decode(make_token(), REGION, USERPOOL_ID)['sub'] == 'user-sub'
    assert 'Using the cached JWKS' in caplog.text
    assert jwks_server.requests == 2
    # The failing endpoint is not retried on every request...
    decode(make_token(), REGION, USERPOOL_ID)
    assert jwks_server.requests == 2
    # ...only after KEYS_REFRESH_INTERVAL.
    time.sleep(0.35)
    jwks_server.status = 200
    decode(make_token(), REGION, USERPOOL_ID)
    assert jwks_server.requests == 3


def test_cache_size_is_limited(api, jwks_server, monkeypatch):
    _, _, get_keys = api
    get = get_keys if get_keys is jwt_sync.get_keys else (lambda url: _run(get_keys(url)))
    monkeypatch.setattr(constants, 'KEYS_CACHE_SIZE', 2)
    urls = [f'{jwks_server.base_url}/{i}/jwks.json' for i in range(3)]
    for url in urls:
        get(url)
    assert get_keys.cache_info().currsize == 2
    get(urls[2])
    assert jwks_server.requests == 3
    get(urls[0])  # dropped, so downloaded again
    assert jwks_server.requests == 4


def test_cache_info(api, jwks_server, make_token):
    decode, _, get_keys = api
    for _ in range(3):
        decode(make_token(), REGION, USERPOOL_ID)
    info = get_keys.cache_info()
    assert (info.hits, info.misses, info.currsize) == (2, 1, 1)
    assert info.maxsize == constants.KEYS_CACHE_SIZE
    get_keys.cache_clear()
    assert get_keys.cache_info().currsize == 0


@pytest.mark.parametrize('status', [400, 403, 404])
def test_client_error_is_remembered(api, jwks_server, make_token, monkeypatch, status):
    decode, _, _ = api
    monkeypatch.setattr(constants, 'KEYS_REFRESH_INTERVAL', 0.3)
    jwks_server.status = status
    with pytest.raises(JWKSError, match=str(status)):
        decode(make_token(), REGION, USERPOOL_ID)
    jwks_server.status = 200
    with pytest.raises(JWKSError, match=str(status)):
        decode(make_token(), REGION, USERPOOL_ID)
    assert jwks_server.requests == 1
    time.sleep(0.35)
    assert decode(make_token(), REGION, USERPOOL_ID)['sub'] == 'user-sub'
    assert jwks_server.requests == 2


@pytest.mark.parametrize('status', [408, 429, 500, 503])
def test_temporary_error_is_not_remembered(api, jwks_server, make_token, status):
    decode, _, _ = api
    jwks_server.status = status
    with pytest.raises(JWKSError):
        decode(make_token(), REGION, USERPOOL_ID)
    jwks_server.status = 200
    assert decode(make_token(), REGION, USERPOOL_ID)['sub'] == 'user-sub'
