import os
import cognitojwt


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
