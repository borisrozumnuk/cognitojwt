[![Build Status](https://travis-ci.org/borisrozumnuk/cognitojwt.svg?branch=master)](https://travis-ci.org/borisrozumnuk/cognitojwt)

# Decode and verify [Amazon Cognito](https://aws.amazon.com/cognito/) JWT tokens

### Note: tested on Python >= 3.6, compatible with PEP-492 (async/await coroutines syntax)

### Installation

Package works in two modes: synchronous - [requests](https://github.com/requests/requests) as http-client and asynchronous - [aiohttp](https://github.com/aio-libs/aiohttp) as http-client.
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
