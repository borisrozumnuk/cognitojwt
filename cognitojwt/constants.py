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

# Tokens longer than this (bytes) are rejected before they are parsed. It is
# above the largest token joserfc itself accepts, so no valid token is affected.
MAX_TOKEN_SIZE = 128 * 1024

# A token whose "iat" is further in the future than this (seconds, on top of
# "leeway") is rejected. Generous, so a slightly wrong server clock is harmless.
MAX_IAT_SKEW = 300

# The JWKS is downloaded again when it is older than this (seconds), so keys
# removed from the user pool stop being trusted. If the download fails, the old
# keys are still used and the download is retried after KEYS_REFRESH_INTERVAL.
KEYS_MAX_AGE = 6 * 60 * 60

# Maximal number of JWKS (user pools) kept in the cache; the least recently
# used one is dropped first.
KEYS_CACHE_SIZE = 256
