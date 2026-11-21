import time

import pytest

from cognitojwt import CognitoJWTException, token_utils

from .conftest import APP_CLIENT_ID, ISSUER, REGION, USERPOOL_ID


def test_get_headers(make_token, private_key):
    headers = token_utils.get_unverified_headers(make_token())
    assert headers['kid'] == private_key.kid
    assert headers['alg'] == 'RS256'


def test_get_claims(make_token):
    claims_id = token_utils.get_unverified_claims(make_token('id'))
    assert {'sub', 'aud', 'exp'} <= claims_id.keys()
    claims_access = token_utils.get_unverified_claims(make_token('access'))
    assert {'sub', 'client_id', 'exp'} <= claims_access.keys()


@pytest.mark.parametrize('token', ['garbage', 'a.b.c', 'é.é.é'])
def test_unverified_malformed(token):
    with pytest.raises(CognitoJWTException):
        token_utils.get_unverified_headers(token)
    with pytest.raises(CognitoJWTException):
        token_utils.get_unverified_claims(token)


def test_check_expired():
    exp = int(time.time()) + 100
    token_utils.check_expired(exp, False)
    exp = int(time.time()) - 100
    with pytest.raises(CognitoJWTException):
        token_utils.check_expired(exp, False)
    token_utils.check_expired(exp, True)
    token_utils.check_expired(exp, testmode=True)
    for bad in (None, '123', True):
        with pytest.raises(CognitoJWTException):
            token_utils.check_expired(bad)


def test_check_client_id(make_token):
    for token_use in ('id', 'access'):
        claims = token_utils.get_unverified_claims(make_token(token_use))
        token_utils.check_client_id(claims, APP_CLIENT_ID)
        token_utils.check_client_id(claims, ['1001001', APP_CLIENT_ID])
        token_utils.check_client_id(claims, {APP_CLIENT_ID})
        with pytest.raises(CognitoJWTException):
            token_utils.check_client_id(claims, '1001001')
        with pytest.raises(CognitoJWTException):
            token_utils.check_client_id(claims, f'100{APP_CLIENT_ID}001')
        with pytest.raises(CognitoJWTException):
            # Substring of the client id must not match.
            token_utils.check_client_id(claims, APP_CLIENT_ID[:-1] + 'X' + APP_CLIENT_ID)


def test_check_client_id_aud_list():
    token_utils.check_client_id({'token_use': 'id', 'aud': ['x', APP_CLIENT_ID]}, APP_CLIENT_ID)
    with pytest.raises(CognitoJWTException):
        token_utils.check_client_id({'token_use': 'id', 'aud': ['x']}, {APP_CLIENT_ID})


@pytest.mark.parametrize('claims', [
    {},
    {'token_use': 'refresh', 'aud': APP_CLIENT_ID},
    {'token_use': ['id'], 'aud': APP_CLIENT_ID},
    {'token_use': 'id'},
    {'token_use': 'access', 'aud': APP_CLIENT_ID},
])
def test_check_client_id_invalid_claims(claims):
    with pytest.raises(CognitoJWTException):
        token_utils.check_client_id(claims, APP_CLIENT_ID)


def test_check_issuer():
    token_utils.check_issuer({'iss': ISSUER}, REGION, USERPOOL_ID)
    with pytest.raises(CognitoJWTException):
        token_utils.check_issuer({'iss': ISSUER + 'x'}, REGION, USERPOOL_ID)
    with pytest.raises(CognitoJWTException):
        token_utils.check_issuer({}, REGION, USERPOOL_ID)


def test_check_expired_at_exp(monkeypatch):
    # RFC 7519: the token is no longer valid at "exp" itself.
    monkeypatch.setattr(token_utils.time, 'time', lambda: 1000.0)
    token_utils.check_expired(1001)
    with pytest.raises(CognitoJWTException, match='expired'):
        token_utils.check_expired(1000)


@pytest.mark.parametrize('payload, message', [
    (b'not json', 'not valid JSON'),
    (b'[1, 2]', 'not a JSON object'),
])
def test_unverified_claims_bad_payload(payload, message):
    from joserfc.util import urlsafe_b64encode
    header = urlsafe_b64encode(b'{"alg": "RS256", "kid": "k"}')
    token = b'.'.join([header, urlsafe_b64encode(payload), b'c2ln'])
    with pytest.raises(CognitoJWTException, match=message):
        token_utils.get_unverified_claims(token)


def test_unverified_oversized(make_token, monkeypatch):
    token = make_token()
    monkeypatch.setattr(token_utils.constants, 'MAX_TOKEN_SIZE', len(token) - 1)
    with pytest.raises(CognitoJWTException, match='too large'):
        token_utils.get_unverified_headers(token)


@pytest.mark.parametrize('region, userpool_id', [
    ('eu-west-1', 'eu-west-1_TestPool1'),
    ('us-gov-west-1', 'us-gov-west-1_abc123'),
    ('ap-southeast-7', 'ap-southeast-7_A1b2C3'),
    ('cn-north-1', 'cn-north-1_X'),
])
def test_valid_region_and_pool(region, userpool_id):
    from cognitojwt import _jwks
    url, custom = _jwks.get_keys_url(region, userpool_id)
    assert url == f'https://cognito-idp.{region}.amazonaws.com/{userpool_id}/.well-known/jwks.json'
    assert not custom


def test_plain_http_jwks_warns(monkeypatch):
    import warnings

    from cognitojwt import _jwks, constants
    monkeypatch.setenv(constants.JWKS_PATH_ENV, 'http://jwks.example.com/jwks.json')
    with pytest.warns(UserWarning, match='plain HTTP'):
        _jwks.get_keys_url(REGION, USERPOOL_ID)
    for url in ('https://jwks.example.com/jwks.json', 'http://localhost:9229/jwks.json',
                'http://127.0.0.1/jwks.json', 'http://[::1]/jwks.json', 'http://cognito.localhost/j',
                '/etc/jwks.json'):
        monkeypatch.setenv(constants.JWKS_PATH_ENV, url)
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            _jwks.get_keys_url(REGION, USERPOOL_ID)
