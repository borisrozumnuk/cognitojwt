PUBLIC_KEYS_URL_TEMPLATE = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'
ISSUER_TEMPLATE = 'https://cognito-idp.{}.amazonaws.com/{}'

# Environment variable with a path (or URL) of a jwks.json file that overrides
# the default Cognito JWKS endpoint, e.g. for deployments without internet access.
JWKS_PATH_ENV = 'AWS_COGNITO_JWKS_PATH'

# Cognito signs ID and access tokens with RS256 only.
ALLOWED_ALGORITHMS = ('RS256',)

# Timeout (seconds) for downloading the JWKS.
HTTP_TIMEOUT = 10

# Minimal interval (seconds) between JWKS re-downloads triggered by an unknown
# "kid" (key rotation). Protects against forcing a download per request with
# forged tokens.
KEYS_REFRESH_INTERVAL = 60
