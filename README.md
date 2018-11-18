# Decode and verify Amazon Cognito JWT tokens

### Note: tested on Python >= 3.6, compatible with PEP-492 (async/await coroutines syntax)

### Installation

```
pip install cognitojwt
```

### Usage

```
import cognitojwt

id_token = '<YOUR_TOKEN_HERE>'
REGION = '**-****-*'
USERPOOL_ID = 'eu-west-1_*******'
APP_CLIENT_ID = '1p3*********'

verified_claims = cognitojwt.decode(
    id_token,
    REGION,
    USERPOOL_ID,
    APP_CLIENT_ID,
    testmode=True # disable token expiration checking for testing purposes
)

# async
verified_claims = await cognitojwt.decode_async(
    id_token,
    REGION,
    USERPOOL_ID,
    APP_CLIENT_ID,
    testmode=True # disable token expiration checking for testing purposes
)

```