import asyncio
import json
import warnings

import pytest

from cognitojwt import (
    CognitoJWTVerifier, InvalidClaimError, InvalidUserPoolError, TokenExpiredError, constants,
    jwt_async, jwt_sync,
)

from .conftest import APP_CLIENT_ID, REGION, USERPOOL_ID, jwks_for


@pytest.fixture(params=['sync', 'async'])
def verify(request):
    if request.param == 'sync':
        return lambda verifier, token, **kw: verifier.verify(token, **kw)
    return lambda verifier, token, **kw: asyncio.run(verifier.verify_async(token, **kw))


def test_verify(verify, jwks_server, make_token):
    verifier = CognitoJWTVerifier(REGION, USERPOOL_ID, APP_CLIENT_ID, token_use='access')
    assert verify(verifier, make_token('access'))['token_use'] == 'access'
    with pytest.raises(InvalidClaimError, match='token_use'):
        verify(verifier, make_token('id'))
    with pytest.raises(InvalidClaimError, match='client id'):
        verify(verifier, make_token('access', client_id='another-client'))
    with pytest.raises(InvalidClaimError, match='user pool'):
        verify(verifier, make_token('access', iss='https://example.com'))


def test_own_cache(verify, jwks_server, make_token):
    first = CognitoJWTVerifier(REGION, USERPOOL_ID)
    second = CognitoJWTVerifier(REGION, USERPOOL_ID)
    verify(first, make_token())
    verify(first, make_token())
    verify(second, make_token())
    assert jwks_server.requests == 2
    # The module-level cache of decode() is not used.
    assert jwt_sync.get_keys.cache_info().currsize == 0
    assert jwt_async.get_keys_async.cache_info().currsize == 0
    first.clear_cache()
    verify(first, make_token())
    assert jwks_server.requests == 3


def test_leeway_and_testmode(verify, jwks_server, make_token):
    import time
    token = make_token(exp=int(time.time()) - 10)
    with pytest.raises(TokenExpiredError):
        verify(CognitoJWTVerifier(REGION, USERPOOL_ID), token)
    assert verify(CognitoJWTVerifier(REGION, USERPOOL_ID, leeway=30), token)['sub'] == 'user-sub'
    assert verify(CognitoJWTVerifier(REGION, USERPOOL_ID), token, testmode=True)['sub'] == 'user-sub'
    with pytest.raises(ValueError, match='leeway'):
        CognitoJWTVerifier(REGION, USERPOOL_ID, leeway=-5)


def test_jwks_url_per_verifier(verify, tmp_path, make_token, private_key):
    path = tmp_path / 'jwks.json'
    path.write_text(json.dumps(jwks_for(private_key)))
    # Two verifiers with their own JWKS in one process (impossible with the environment variable).
    local = CognitoJWTVerifier('local', 'local_pool', jwks_url=str(path))
    token = make_token(iss='http://localhost:9229/local_pool')
    assert verify(local, token)['sub'] == 'user-sub'  # iss is not checked by default
    strict = CognitoJWTVerifier('local', 'local_pool', jwks_url=str(path), issuer='http://localhost:9229/local_pool')
    assert verify(strict, token)['sub'] == 'user-sub'
    with pytest.raises(InvalidClaimError, match='user pool'):
        verify(strict, make_token())


def test_environment_variable_is_used(verify, jwks_file, make_token):
    verifier = CognitoJWTVerifier('local', 'local_pool')
    assert verifier.jwks_url == str(jwks_file)
    assert verify(verifier, make_token())['sub'] == 'user-sub'


def test_invalid_pool_is_rejected_at_creation():
    with pytest.raises(InvalidUserPoolError):
        CognitoJWTVerifier('evil.example#', USERPOOL_ID)


def test_warnings_at_creation():
    with pytest.warns(UserWarning, match='app_client_id is empty'):
        verifier = CognitoJWTVerifier(REGION, USERPOOL_ID, '')
    assert verifier.app_client_id is None
    with pytest.warns(UserWarning, match='plain HTTP'):
        CognitoJWTVerifier(REGION, USERPOOL_ID, jwks_url='http://jwks.example.com/jwks.json')
    with warnings.catch_warnings():
        warnings.simplefilter('error')
        CognitoJWTVerifier(REGION, USERPOOL_ID, APP_CLIENT_ID)


def test_repr():
    verifier = CognitoJWTVerifier(REGION, USERPOOL_ID)
    assert repr(verifier) == (
        f"CognitoJWTVerifier('{REGION}', '{USERPOOL_ID}', "
        f"jwks_url='{constants.PUBLIC_KEYS_URL_TEMPLATE.format(REGION, USERPOOL_ID)}')"
    )
