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
