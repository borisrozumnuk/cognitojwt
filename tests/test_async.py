import asyncio

import pytest

from cognitojwt import jwt_async

from .conftest import REGION, USERPOOL_ID


@pytest.mark.asyncio
async def test_concurrent_requests_share_one_download(jwks_server, make_token):
    token = make_token()
    results = await asyncio.gather(*(
        jwt_async.decode_async(token, REGION, USERPOOL_ID) for _ in range(20)
    ))
    assert all(r['sub'] == 'user-sub' for r in results)
    assert jwks_server.requests == 1
    assert not jwt_async._in_flight


@pytest.mark.asyncio
async def test_get_keys_async(jwks_server, private_key):
    url = jwks_server.base_url + '/jwks.json'
    keys = await jwt_async.get_keys_async(url)
    assert [k['kid'] for k in keys] == [private_key.kid]
    assert await jwt_async.get_keys_async(url) is keys
    await jwt_async.get_keys_async(url, force_refresh=True)
    assert jwks_server.requests == 2
