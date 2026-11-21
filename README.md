# Decode and verify [Amazon Cognito](https://aws.amazon.com/cognito/) JWT tokens

# Repository is archived. You can utilize any stable JWT library that supports JWKS.

### Note: requires Python >= 3.8, compatible with PEP-492 (async/await coroutines syntax)

### Installation

Package works in two modes: synchronous - [requests](https://github.com/psf/requests) as http-client and asynchronous - [aiohttp](https://github.com/aio-libs/aiohttp) as http-client.
In order to avoid installing unnecessary dependencies I separated installation flow into two modes:

* Async mode - `pip install cognitojwt[async]`
* Sync mode - `pip install cognitojwt[sync]`

### Usage

```python
import cognitojwt

id_token = '<YOUR_TOKEN_HERE>'
REGION = '**-****-*'
USERPOOL_ID = 'eu-west-1_*******'
APP_CLIENT_ID = '1p3*********'

# Sync mode
verified_claims: dict = cognitojwt.decode(
    id_token,
    REGION,
    USERPOOL_ID,
    app_client_id=APP_CLIENT_ID,  # Optional
    testmode=True  # Disable token expiration check for testing purposes
)

# Async mode
verified_claims: dict = await cognitojwt.decode_async(
    id_token,
    REGION,
    USERPOOL_ID,
    app_client_id=APP_CLIENT_ID,  # Optional
    testmode=True  # Disable token expiration check for testing purposes
)

```

Any verification failure (malformed token, bad signature, unknown key, expired token,
wrong issuer or client id, unavailable JWKS) raises `cognitojwt.CognitoJWTException`.

The following is verified:

* the RS256 signature against the user pool JWKS (`https://cognito-idp.<region>.amazonaws.com/<userpool_id>/.well-known/jwks.json`);
* `exp` (skipped when `testmode=True`);
* `iss` must be the user pool (skipped when a custom JWKS is set via `AWS_COGNITO_JWKS_PATH`);
* `aud` (ID token) / `client_id` (access token), when `app_client_id` is passed.

The JWKS is downloaded once and cached in memory. When a token is signed with a key that
is not in the cached JWKS (key rotation), the JWKS is downloaded again, at most once a minute.

Note: if the application is deployed inside a private vpc without internet gateway, the application will not be able to download the JWKS file.
In this case set the `AWS_COGNITO_JWKS_PATH` environment variable referencing the absolute or relative path of the jwks.json file.

It is possible to allow multiple app client ids by passing the value as a Container instance such as a list or tuple:
```python
ALLOWED_CLIENT_IDS = ('client_one', 'client_two')

verified_claims: dict = cognitojwt.decode(
    id_token,
    REGION,
    USERPOOL_ID,
    app_client_id=ALLOWED_CLIENT_IDS,
    testmode=True  # Disable token expiration check for testing purposes
)
```

### Development

```bash
pip install -e '.[test]'
pytest
```

Tests use locally generated keys and don't need access to AWS.
