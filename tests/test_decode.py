"""Behaviour shared by ``decode`` and ``decode_async`` (both run on every test)."""
import asyncio
import json
import time

import pytest
from joserfc import jwk

import cognitojwt
from cognitojwt import CognitoJWTException, constants, jwt_async, jwt_sync

from .conftest import APP_CLIENT_ID, REGION, USERPOOL_ID, jwks_for


def _run_async(func):
    def wrapper(*args, **kwargs):
        return asyncio.run(func(*args, **kwargs))
    return wrapper


@pytest.fixture(params=['sync', 'async'])
def mode(request):
    return request.param


@pytest.fixture
def decode(mode):
    return cognitojwt.decode if mode == 'sync' else _run_async(cognitojwt.decode_async)


@pytest.fixture
def get_public_key(mode):
    return jwt_sync.get_public_key if mode == 'sync' else _run_async(jwt_async.get_public_key_async)


def test_public_api():
    assert set(cognitojwt.__all__) == {
        'CognitoJWTException', 'CognitoJWTVerifier', 'decode', 'decode_async',
        'InvalidClaimError', 'InvalidSignatureError', 'InvalidUserPoolError', 'JWKSError',
        'MalformedTokenError', 'TokenExpiredError',
    }
    assert cognitojwt.decode is jwt_sync.decode
    assert cognitojwt.decode_async is jwt_async.decode_async


@pytest.mark.parametrize('token_use', ['id', 'access'])
def test_decode_from_url(decode, jwks_server, make_token, token_use):
    token = make_token(token_use)
    claims = decode(token, REGION, USERPOOL_ID)
    assert claims['token_use'] == token_use
    assert claims['sub'] == 'user-sub'
    assert decode(token, REGION, USERPOOL_ID, APP_CLIENT_ID) == claims
    assert decode(token, REGION, USERPOOL_ID, app_client_id=['x', APP_CLIENT_ID]) == claims


def test_jwks_is_cached(decode, jwks_server, make_token):
    token = make_token()
    for _ in range(3):
        decode(token, REGION, USERPOOL_ID)
    assert jwks_server.requests == 1


def test_decode_from_local_file(decode, jwks_file, make_token):
    claims = decode(make_token('access'), REGION, USERPOOL_ID, APP_CLIENT_ID)
    assert claims['client_id'] == APP_CLIENT_ID


def test_decode_jwks_env_accepts_url(decode, jwks_server, monkeypatch, make_token):
    monkeypatch.setenv(constants.JWKS_PATH_ENV, jwks_server.base_url + '/custom/jwks.json')
    assert decode(make_token(), REGION, USERPOOL_ID)['sub'] == 'user-sub'


def test_decode_bytes_token(decode, jwks_file, make_token):
    assert decode(make_token().encode(), REGION, USERPOOL_ID)['sub'] == 'user-sub'


def test_expired_token(decode, jwks_file, make_token):
    token = make_token(exp=int(time.time()) - 10)
    with pytest.raises(CognitoJWTException, match='expired'):
        decode(token, REGION, USERPOOL_ID)
    assert decode(token, REGION, USERPOOL_ID, testmode=True)['sub'] == 'user-sub'


def test_missing_exp(decode, jwks_file, make_token):
    token = make_token(drop=['exp'])
    with pytest.raises(CognitoJWTException, match='exp'):
        decode(token, REGION, USERPOOL_ID)
    assert decode(token, REGION, USERPOOL_ID, testmode=True)['sub'] == 'user-sub'


def test_wrong_client_id(decode, jwks_file, make_token):
    with pytest.raises(CognitoJWTException, match='client id'):
        decode(make_token(), REGION, USERPOOL_ID, app_client_id='another-client')
    with pytest.raises(CognitoJWTException, match='client id'):
        decode(make_token('access'), REGION, USERPOOL_ID, app_client_id=('a', 'b'))


def test_wrong_issuer(decode, jwks_server, make_token):
    token = make_token(iss='https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_OtherPool')
    with pytest.raises(CognitoJWTException, match='user pool'):
        decode(token, REGION, USERPOOL_ID)
    with pytest.raises(CognitoJWTException, match='user pool'):
        decode(make_token(drop=['iss']), REGION, USERPOOL_ID)


def test_issuer_not_checked_with_custom_jwks(decode, jwks_file, make_token):
    # E.g. a local Cognito emulator with its own issuer.
    token = make_token(iss='http://localhost:9229/local_pool')
    assert decode(token, REGION, USERPOOL_ID)['iss'] == 'http://localhost:9229/local_pool'


def test_tampered_payload(decode, jwks_file, make_token):
    header, _payload, signature = make_token().split('.')
    forged = make_token(sub='admin').split('.')[1]
    with pytest.raises(CognitoJWTException, match='Signature verification failed'):
        decode('.'.join([header, forged, signature]), REGION, USERPOOL_ID)


def test_signed_with_unknown_key(decode, jwks_file, make_token, other_key):
    with pytest.raises(CognitoJWTException, match='Public key not found'):
        decode(make_token(key=other_key), REGION, USERPOOL_ID)


def test_forged_kid(decode, jwks_file, make_token, other_key, private_key):
    # Signed with a foreign key, but claims the kid of the published key.
    token = make_token(key=other_key, headers={'kid': private_key.kid})
    with pytest.raises(CognitoJWTException, match='Signature verification failed'):
        decode(token, REGION, USERPOOL_ID)


@pytest.mark.parametrize('alg', ['none', 'HS256'])
def test_algorithm_confusion(decode, jwks_file, make_token, alg):
    _header, payload, _ = make_token().split('.')
    from joserfc.util import urlsafe_b64encode
    forged_header = urlsafe_b64encode(json.dumps({'alg': alg, 'kid': 'test-kid-1'}).encode()).decode()
    with pytest.raises(CognitoJWTException, match='Signature verification failed'):
        decode('.'.join([forged_header, payload, 'c2ln']), REGION, USERPOOL_ID)


@pytest.mark.parametrize('token', ['', 'garbage', 'a.b', 'a.b.c', None, 123])
def test_malformed_token(decode, jwks_file, token):
    with pytest.raises(CognitoJWTException):
        decode(token, REGION, USERPOOL_ID)


def test_missing_kid(decode, jwks_file, make_token, private_key):
    from joserfc import jwt
    token = jwt.encode({'alg': 'RS256'}, {'exp': int(time.time()) + 60}, private_key)
    with pytest.raises(CognitoJWTException, match='kid'):
        decode(token, REGION, USERPOOL_ID)


def test_key_rotation_refetches_jwks(decode, jwks_server, make_token, private_key, monkeypatch):
    decode(make_token(), REGION, USERPOOL_ID)
    assert jwks_server.requests == 1

    new_key = jwk.RSAKey.generate_key(2048, parameters={'kid': 'rotated', 'alg': 'RS256'})
    jwks_server.jwks = jwks_for(private_key, new_key)
    token = make_token(key=new_key)

    # Right after a download the JWKS isn't re-fetched, so forged kids can't force downloads.
    with pytest.raises(CognitoJWTException, match='Public key not found'):
        decode(token, REGION, USERPOOL_ID)
    assert jwks_server.requests == 1

    monkeypatch.setattr(constants, 'KEYS_REFRESH_INTERVAL', 0)
    assert decode(token, REGION, USERPOOL_ID)['sub'] == 'user-sub'
    assert jwks_server.requests == 2


def test_jwks_http_error(decode, jwks_server, make_token):
    jwks_server.status = 500
    with pytest.raises(CognitoJWTException, match='Unable to download JWKS'):
        decode(make_token(), REGION, USERPOOL_ID)
    # Failures are not cached.
    jwks_server.status = 200
    assert decode(make_token(), REGION, USERPOOL_ID)['sub'] == 'user-sub'


def test_jwks_unreachable(decode, monkeypatch, make_token):
    monkeypatch.setenv(constants.JWKS_PATH_ENV, 'http://127.0.0.1:1/jwks.json')
    with pytest.raises(CognitoJWTException, match='Unable to download JWKS'):
        decode(make_token(), REGION, USERPOOL_ID)


@pytest.mark.parametrize('content', ['not json', '[]', '{"foo": 1}', '{"keys": null}'])
def test_invalid_jwks_file(decode, jwks_file, make_token, content):
    jwks_file.write_text(content)
    with pytest.raises(CognitoJWTException, match='Invalid JWKS'):
        decode(make_token(), REGION, USERPOOL_ID)


def test_missing_jwks_file(decode, tmp_path, monkeypatch, make_token):
    monkeypatch.setenv(constants.JWKS_PATH_ENV, str(tmp_path / 'nope.json'))
    with pytest.raises(CognitoJWTException, match='Unable to read JWKS file'):
        decode(make_token(), REGION, USERPOOL_ID)


def test_get_public_key(get_public_key, jwks_server, make_token, private_key):
    key = get_public_key(make_token(), REGION, USERPOOL_ID)
    assert isinstance(key, jwk.RSAKey)
    assert key.kid == private_key.kid
    assert not key.is_private


@pytest.mark.parametrize('region, userpool_id', [
    ('evil.example#', 'eu-west-1_TestPool1'),
    ('evil.example/', 'eu-west-1_TestPool1'),
    ('eu-west-1', 'eu-west-1_x/../../other'),
    ('eu-west-1', 'eu-west-1_x?y'),
    ('eu-west-1', 'us-east-1_TestPool1'),
    ('eu-west-1', 'TestPool1'),
    (None, USERPOOL_ID),
    (REGION, None),
])
def test_invalid_region_or_pool_is_not_requested(decode, jwks_server, make_token, region, userpool_id):
    # These would point the JWKS URL to another host or path.
    with pytest.raises(CognitoJWTException, match=r'Invalid (region|user pool id)'):
        decode(make_token(), region, userpool_id)
    assert jwks_server.requests == 0


def test_custom_jwks_skips_pool_validation(decode, jwks_file, make_token):
    # Local emulators may use any region and pool id.
    assert decode(make_token(), 'local', 'local_pool')['sub'] == 'user-sub'


def test_oversized_token(decode, jwks_file, make_token, monkeypatch):
    token = make_token(padding='x' * 2000)
    monkeypatch.setattr(constants, 'MAX_TOKEN_SIZE', len(token) - 1)
    with pytest.raises(CognitoJWTException, match='too large'):
        decode(token, REGION, USERPOOL_ID)
    with pytest.raises(CognitoJWTException, match='too large'):
        decode(token.encode(), REGION, USERPOOL_ID)
    monkeypatch.setattr(constants, 'MAX_TOKEN_SIZE', len(token))
    assert decode(token, REGION, USERPOOL_ID)['sub'] == 'user-sub'


@pytest.mark.parametrize('app_client_id', ['', [], ()])
def test_empty_app_client_id_warns(decode, jwks_file, make_token, app_client_id):
    token = make_token(aud='another-client')
    with pytest.warns(UserWarning, match='app_client_id is empty'):
        assert decode(token, REGION, USERPOOL_ID, app_client_id=app_client_id)['sub'] == 'user-sub'


def test_invalid_key_in_jwks(decode, jwks_file, make_token):
    jwks_file.write_text(json.dumps({'keys': [{'kid': 'test-kid-1', 'kty': 'RSA'}]}))
    with pytest.raises(CognitoJWTException, match='Invalid public key'):
        decode(make_token(), REGION, USERPOOL_ID)


@pytest.mark.parametrize('case, error', [
    ('expired', cognitojwt.TokenExpiredError),
    ('no_exp', cognitojwt.InvalidClaimError),
    ('wrong_client', cognitojwt.InvalidClaimError),
    ('wrong_issuer', cognitojwt.InvalidClaimError),
    ('tampered', cognitojwt.InvalidSignatureError),
    ('unknown_key', cognitojwt.InvalidSignatureError),
    ('malformed', cognitojwt.MalformedTokenError),
    ('no_kid', cognitojwt.MalformedTokenError),
    ('bad_region', cognitojwt.InvalidUserPoolError),
    ('jwks_down', cognitojwt.JWKSError),
])
def test_error_types(decode, jwks_server, make_token, other_key, private_key, case, error):
    from joserfc import jwt
    kwargs = {}
    region = REGION
    token = make_token()
    if case == 'expired':
        token = make_token(exp=int(time.time()) - 10)
    elif case == 'no_exp':
        token = make_token(drop=['exp'])
    elif case == 'wrong_client':
        kwargs['app_client_id'] = 'another-client'
    elif case == 'wrong_issuer':
        token = make_token(iss='https://example.com')
    elif case == 'tampered':
        header, _, signature = token.split('.')
        token = '.'.join([header, make_token(sub='admin').split('.')[1], signature])
    elif case == 'unknown_key':
        token = make_token(key=other_key)
    elif case == 'malformed':
        token = 'garbage'
    elif case == 'no_kid':
        token = jwt.encode({'alg': 'RS256'}, {'exp': int(time.time()) + 60}, private_key)
    elif case == 'bad_region':
        region = 'evil.example#'
    elif case == 'jwks_down':
        jwks_server.status = 503
    with pytest.raises(error) as info:
        decode(token, region, USERPOOL_ID, **kwargs)
    assert isinstance(info.value, CognitoJWTException)


def test_leeway(decode, jwks_file, make_token):
    token = make_token(exp=int(time.time()) - 10)
    assert decode(token, REGION, USERPOOL_ID, leeway=30)['sub'] == 'user-sub'
    with pytest.raises(cognitojwt.TokenExpiredError):
        decode(token, REGION, USERPOOL_ID, leeway=5)
    with pytest.raises(ValueError, match='leeway'):
        decode(make_token(), REGION, USERPOOL_ID, leeway=-1)


def test_iat_in_the_future(decode, jwks_file, make_token):
    now = int(time.time())
    with pytest.raises(cognitojwt.InvalidClaimError, match='future'):
        decode(make_token(iat=now + 3600), REGION, USERPOOL_ID)
    # A slightly wrong clock is tolerated, and leeway adds to it.
    assert decode(make_token(iat=now + 60), REGION, USERPOOL_ID)['sub'] == 'user-sub'
    assert decode(make_token(iat=now + 3600), REGION, USERPOOL_ID, leeway=3600)['sub'] == 'user-sub'
    assert decode(make_token(iat=now + 3600), REGION, USERPOOL_ID, testmode=True)['sub'] == 'user-sub'
    assert decode(make_token(drop=['iat']), REGION, USERPOOL_ID)['sub'] == 'user-sub'
    with pytest.raises(cognitojwt.InvalidClaimError, match='iat'):
        decode(make_token(iat='soon'), REGION, USERPOOL_ID)


def test_token_use(decode, jwks_file, make_token):
    assert decode(make_token('id'), REGION, USERPOOL_ID, token_use='id')['token_use'] == 'id'
    with pytest.raises(cognitojwt.InvalidClaimError, match='token_use'):
        decode(make_token('access'), REGION, USERPOOL_ID, token_use='id')
    with pytest.raises(cognitojwt.InvalidClaimError, match='token_use'):
        decode(make_token('id'), REGION, USERPOOL_ID, APP_CLIENT_ID, token_use='access')
    for token_use in ('id', 'access'):
        claims = decode(make_token(token_use), REGION, USERPOOL_ID, token_use=('id', 'access'))
        assert claims['token_use'] == token_use
