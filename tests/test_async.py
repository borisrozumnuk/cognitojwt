import asyncio
import gc

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


@pytest.mark.asyncio
async def test_failed_download_with_cancelled_callers_is_not_logged(jwks_server, make_token):
    loop = asyncio.get_running_loop()
    reported = []
    loop.set_exception_handler(lambda _loop, context: reported.append(context))
    jwks_server.status = 500
    jwks_server.delay = 0.1

    caller = asyncio.ensure_future(jwt_async.decode_async(make_token(), REGION, USERPOOL_ID))
    await asyncio.sleep(0.02)
    (download,) = jwt_async._in_flight.values()
    caller.cancel()
    await asyncio.wait([download])
    # Drop every reference, so the failed download is garbage collected now.
    del caller, download
    gc.collect()
    await asyncio.sleep(0)
    assert not reported
