import os
import tempfile

import requests

import cognitojwt
from jose.backends import RSAKey

from cognitojwt.constants import PUBLIC_KEYS_URL_TEMPLATE

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


def test_get_public_key():

    keys_url = PUBLIC_KEYS_URL_TEMPLATE.format(AWS_COGNITO_REGION, AWS_COGNITO_USERPOOL_ID)
    r = requests.get(keys_url)
    keys_response = r.text

    with tempfile.NamedTemporaryFile(suffix='.json') as tf:
        tf.write(keys_response.encode('utf-8'))
        tf.seek(0)
        os.environ['AWS_COGNITO_JWKS_PATH'] = tf.name

        pub_key = cognitojwt.jwt_sync.get_public_key(
            TEST_ACCESS_TOKEN,
            AWS_COGNITO_REGION,
            AWS_COGNITO_USERPOOL_ID
        )
        del os.environ['AWS_COGNITO_JWKS_PATH']
    assert isinstance(pub_key, RSAKey)
