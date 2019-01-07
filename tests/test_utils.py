import os
import time
import pytest
from cognitojwt import token_utils, CognitoJWTException


TEST_ID_TOKEN = os.environ['TEST_ID_TOKEN']
TEST_ACCESS_TOKEN = os.environ['TEST_ACCESS_TOKEN']

AWS_COGNITO_APP_CLIENT_ID = os.environ['AWS_COGNITO_APP_CLIENT_ID']


def test_get_headers():
    headers_id = token_utils.get_unverified_headers(TEST_ID_TOKEN)
    assert isinstance(headers_id, dict)
    assert 'kid' in headers_id.keys()
    assert 'alg' in headers_id.keys()
    headers_access = token_utils.get_unverified_headers(TEST_ACCESS_TOKEN)
    assert isinstance(headers_access, dict)
    assert 'kid' in headers_access.keys()
    assert 'alg' in headers_access.keys()


def test_get_claims():
    claims_id = token_utils.get_unverified_claims(TEST_ID_TOKEN)
    assert isinstance(claims_id, dict)
    assert 'sub' in claims_id.keys()
    assert 'aud' in claims_id.keys()
    assert 'exp' in claims_id.keys()
    claims_access = token_utils.get_unverified_claims(TEST_ACCESS_TOKEN)
    assert isinstance(claims_access, dict)
    assert 'sub' in claims_access.keys()
    assert 'client_id' in claims_access.keys()
    assert 'exp' in claims_access.keys()


def test_check_expired():
    exp = int(time.time()) + 100
    token_utils.check_expired(exp, False)
    exp = int(time.time()) - 100
    with pytest.raises(CognitoJWTException):
        token_utils.check_expired(exp, False)
    token_utils.check_expired(exp, True)


def test_check_client_id():
    claims = token_utils.get_unverified_claims(TEST_ACCESS_TOKEN)
    token_utils.check_client_id(claims, AWS_COGNITO_APP_CLIENT_ID)
    with pytest.raises(CognitoJWTException):
        token_utils.check_client_id(claims, '1001001')
