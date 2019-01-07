import os
import cognitojwt
from jose.backends import RSAKey


TEST_ID_TOKEN = os.environ['TEST_ID_TOKEN']
TEST_ACCESS_TOKEN = os.environ['TEST_ACCESS_TOKEN']

AWS_COGNITO_REGION = os.environ['AWS_COGNITO_REGION']
AWS_COGNITO_USERPOOL_ID = os.environ['AWS_COGNITO_USERPOOL_ID']
AWS_COGNITO_APP_CLIENT_ID = os.environ['AWS_COGNITO_APP_CLIENT_ID']


async def test_decode_id_token_with_app_id():
    claims = cognitojwt.decode(
        TEST_ID_TOKEN,
        AWS_COGNITO_REGION,
        AWS_COGNITO_USERPOOL_ID,
        AWS_COGNITO_APP_CLIENT_ID,
        testmode=True
    )
    assert isinstance(claims, dict)


async def test_decode_id_token_without_app_id():
    claims = cognitojwt.decode(
        TEST_ID_TOKEN,
        AWS_COGNITO_REGION,
        AWS_COGNITO_USERPOOL_ID,
        testmode=True
    )
    assert isinstance(claims, dict)


async def test_decode_access_token_with_app_id():
    claims = cognitojwt.decode(
        TEST_ID_TOKEN,
        AWS_COGNITO_REGION,
        AWS_COGNITO_USERPOOL_ID,
        AWS_COGNITO_APP_CLIENT_ID,
        testmode=True
    )
    assert isinstance(claims, dict)


def test_decode_access_token_without_app_id():
    claims = cognitojwt.decode(
        TEST_ACCESS_TOKEN,
        AWS_COGNITO_REGION,
        AWS_COGNITO_USERPOOL_ID,
        testmode=True
    )
    assert isinstance(claims, dict)


def test_get_public_key():
    pub_key = cognitojwt.jwt_sync.get_public_key(
        TEST_ACCESS_TOKEN,
        AWS_COGNITO_REGION,
        AWS_COGNITO_USERPOOL_ID
    )
    assert isinstance(pub_key, RSAKey)
