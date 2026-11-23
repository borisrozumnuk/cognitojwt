# Decode and verify [Amazon Cognito](https://aws.amazon.com/cognito/) JWT tokens

### Note: requires Python >= 3.8, compatible with PEP-492 (async/await coroutines syntax)

Documentation: https://borisrozumnuk.github.io/cognitojwt/ (also as [llms.txt](https://borisrozumnuk.github.io/cognitojwt/llms.txt) for LLMs)

### Installation

Package works in two modes: synchronous - [requests](https://github.com/psf/requests) as http-client and asynchronous - [aiohttp](https://github.com/aio-libs/aiohttp) as http-client.
In order to avoid installing unnecessary dependencies I separated installation flow into two modes:

* Async mode - `pip install cognitojwt[async]`
* Sync mode - `pip install cognitojwt[sync]`

### Features
* Amazon Cognito JWT verification
* AWS Cognito User Pools support
* ID token and Access token validation
* JWKS key retrieval and caching
* Automatic JWKS key rotation handling
* Synchronous and asynchronous APIs
* Requests and aiohttp support

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

Optional keyword arguments of `decode` / `decode_async`:

* `token_use='id'` or `'access'` (or both, as a tuple) accepts only that kind of token;
* `leeway=30` tolerates 30 seconds of clock skew for `exp` and `iat`.

### Verifier

`CognitoJWTVerifier` keeps the configuration of one user pool and its own key cache,
so you don't repeat the arguments and can use several pools, each with its own JWKS:

```python
verifier = cognitojwt.CognitoJWTVerifier(
    REGION,
    USERPOOL_ID,
    APP_CLIENT_ID,
    token_use='access',      # Optional
    leeway=30,               # Optional
    jwks_url=None,           # Optional: URL or file path, e.g. of a local emulator
    issuer=None,             # Optional: expected "iss" when jwks_url is set
)

verified_claims: dict = verifier.verify(access_token)              # Sync mode
verified_claims: dict = await verifier.verify_async(access_token)  # Async mode
```

### Errors

Any verification failure raises `cognitojwt.CognitoJWTException` or one of its subclasses:

| Exception | When |
|---|---|
| `MalformedTokenError` | the token can't be parsed (not a JWT, too large, no `kid`) |
| `InvalidSignatureError` | the signature doesn't match, or the key is not in the JWKS |
| `TokenExpiredError` | `exp` is in the past |
| `InvalidClaimError` | a wrong or missing `exp`, `iat`, `iss`, `token_use`, `aud` / `client_id` |
| `InvalidUserPoolError` | `region` or `userpool_id` is not a valid AWS value |
| `JWKSError` | the JWKS can't be downloaded, read or parsed |

`JWKSError` is a problem on the server side (e.g. answer 503); the others mean the
request should be rejected (e.g. 401):

```python
try:
    claims = cognitojwt.decode(token, REGION, USERPOOL_ID, APP_CLIENT_ID)
except cognitojwt.JWKSError:
    ...  # 503
except cognitojwt.CognitoJWTException:
    ...  # 401
```

### What is verified

* the RS256 signature against the user pool JWKS (`https://cognito-idp.<region>.amazonaws.com/<userpool_id>/.well-known/jwks.json`);
* `exp`: the token is rejected from its `exp` time on (skipped when `testmode=True`);
* `iat` must not be in the future, with 5 minutes of tolerance (skipped when `testmode=True`);
* `iss` must be the user pool (skipped when a custom JWKS is set via `AWS_COGNITO_JWKS_PATH`);
* `token_use`, when `token_use` is passed;
* `aud` (ID token) / `client_id` (access token), when `app_client_id` is passed.

### JWKS cache

* The JWKS is downloaded once per user pool and cached in memory; concurrent calls
  (threads or coroutines) share one download.
* When a token is signed with a key that is not in the cached JWKS (key rotation), the
  JWKS is downloaded again, at most once a minute.
* The cached JWKS is downloaded again after 6 hours, so removed keys stop being trusted.
  If that download fails, the old keys are still used (and a warning is logged to the
  `cognitojwt` logger), and the download is retried a minute later.
* A 4xx answer (e.g. a user pool that doesn't exist) is remembered for a minute.
* Up to 256 user pools are cached; the least recently used one is dropped first.

The limits are in `cognitojwt.constants`. `cognitojwt.jwt_sync.get_keys.cache_clear()` /
`cache_info()` (and the same for `jwt_async.get_keys_async`) clear and inspect the cache.

### Private VPC and emulators

If the application is deployed inside a private vpc without internet gateway, the application will not be able to download the JWKS file.
In this case set the `AWS_COGNITO_JWKS_PATH` environment variable referencing the absolute or relative path of the jwks.json file
(or its URL, e.g. of a local Cognito emulator; a plain `http://` URL other than localhost emits a warning).
With this variable set, `region` and `userpool_id` are not validated and `iss` is not checked.
To set a JWKS for one user pool only, pass `jwks_url` (and optionally `issuer`) to `CognitoJWTVerifier`.

### Security notes

* Always pass `app_client_id`. Without it a token issued for any app client of the pool
  is accepted. An empty value (`''`, `[]`) emits a warning, as it is usually a missing setting.
* Don't take the region or the user pool id from the token you are verifying. If you serve
  several pools, look them up in your own list of trusted pools.
* `region` and `userpool_id` must look like real AWS values (`eu-west-1`, `eu-west-1_AbC123`),
  otherwise `InvalidUserPoolError` is raised before anything is downloaded.
* Pass `token_use` when your endpoint expects only access or only ID tokens.
* Tokens larger than 128 KiB are rejected before they are parsed.
* Never use `testmode=True` in production.

### Development

```bash
pip install -e '.[test]'
pytest
ruff check . && mypy   # pip install ruff mypy types-requests
```

Tests use locally generated keys and don't need access to AWS.
