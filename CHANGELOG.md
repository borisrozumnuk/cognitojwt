# Changelog

## 1.7.0

New features. Existing code keeps working: every new parameter is optional and
keyword-only, every new exception is a subclass of `CognitoJWTException`, and the
error messages are unchanged.

### Added
- Exception subclasses, to tell a bad token (401) from an unavailable JWKS (503):
  `MalformedTokenError`, `InvalidSignatureError`, `TokenExpiredError`,
  `InvalidClaimError`, `InvalidUserPoolError` and `JWKSError`.
- `CognitoJWTVerifier(region, userpool_id, app_client_id, *, token_use, leeway, jwks_url,
  issuer, timeout)` with `.verify()` and `.verify_async()`: the configuration of one user
  pool and its own key cache. `jwks_url` sets a custom JWKS per user pool, which the
  `AWS_COGNITO_JWKS_PATH` environment variable can't do.
- `token_use='id'` / `'access'` for `decode` and `decode_async`, to accept only that kind
  of token (AWS recommends checking it).
- `leeway` (seconds) for `decode` and `decode_async`: tolerated clock skew for `exp` and `iat`.
- `get_keys.cache_info()` / `get_keys_async.cache_info()`, as with the former `lru_cache`.
- `token_utils.check_token_use` and `token_utils.check_issued_at`.

### Changed
- `iat` more than 5 minutes (plus `leeway`) in the future is rejected. A missing `iat`
  is still accepted, and `testmode=True` skips the check.
- The cached JWKS is downloaded again after 6 hours (`constants.KEYS_MAX_AGE`), so keys
  removed from the user pool stop being trusted; before, they were trusted until restart.
  If that download fails, the cached keys are still used and a warning is logged.
- The cache holds up to 256 JWKS (`constants.KEYS_CACHE_SIZE`), least recently used dropped first.
- A 4xx answer for the JWKS (e.g. a user pool that doesn't exist) is remembered for a
  minute, so such tokens don't cause a download each. 5xx, 408, 429 and network errors
  are not remembered.
- `decode` is about 2 times faster: the key objects built from the JWKS are cached.
- CI also runs `ruff`, `mypy --strict`, a coverage check and the tests with the oldest
  allowed dependencies; Dependabot keeps the GitHub Actions up to date.

## 1.6.1

Security and robustness fixes. The public API is unchanged.

### Security
- `region` and `userpool_id` are now validated before the JWKS URL is built.
  Before, a value such as `"evil.example#"` moved the download to another host, and
  because the expected issuer is built from the same values, a token signed with the
  attacker's key was accepted. This mattered for apps that take the region or pool id
  from the (unverified) token itself. Values must look like `eu-west-1` and
  `eu-west-1_AbC123` (the pool id must start with the region), otherwise
  `CognitoJWTException` is raised. Not applied when `AWS_COGNITO_JWKS_PATH` is set,
  so local emulators keep working.
- Tokens larger than 128 KiB (`constants.MAX_TOKEN_SIZE`) are rejected before they are
  parsed. This also protects the older `joserfc` versions that are the newest ones
  available on Python 3.8 and 3.9 (GHSA-9pg5-8c7x-5hfx). The newest `joserfc` already
  rejects such tokens, so no valid token is affected.
- A token is rejected at its `exp` time itself, not one second later (RFC 7519).
- An empty `app_client_id` (`''`, `[]`, `()`), usually an unset setting, silently
  disabled the audience check. It still does, for compatibility, but now emits a
  `UserWarning`; pass `None` to skip the check on purpose.
- A custom JWKS URL with plain `http://` (other than localhost) emits a `UserWarning`.

### Fixed
- Concurrent `decode` calls from several threads with an empty cache downloaded the
  JWKS once per thread; they now share one download per URL (as `decode_async` does).
- When every `decode_async` call waiting for a failed JWKS download was cancelled,
  asyncio logged "Task exception was never retrieved".
- Type annotations are complete: `mypy --strict` passes on the package.

### Changed
- Minimal versions of the extras: `requests>=2.32.4` (GHSA-9wx4-h78v-vm56,
  GHSA-9hjg-9r4m-mvj7) and `aiohttp>=3.9.4` (fixes for `ClientSession` CRLF injection
  and older parser issues). Newer `aiohttp` releases fix many more, mostly
  server-side, issues, so keep it up to date in your application.

## 1.6.0

The public API (`decode`, `decode_async`, `CognitoJWTException`, `get_keys`,
`get_keys_async`, `get_public_key`, `get_public_key_async`, `token_utils.*`,
`AWS_COGNITO_JWKS_PATH`) is unchanged and compatible with 1.4.x.

### Fixed
- The migration to `joserfc` was incomplete: the package still imported `python-jose`,
  which is no longer a dependency, so on a clean install `cognitojwt.decode` and
  `cognitojwt.decode_async` silently did not exist. The package now uses only `joserfc`.
- `token_utils.get_unverified_headers` / `get_unverified_claims` called functions
  that don't exist in `joserfc`.
- Only RS256 is accepted, so a token can't choose `none`/`HS256` as its algorithm.
- The `iss` claim is now verified against the user pool, as AWS requires
  (skipped when `AWS_COGNITO_JWKS_PATH` is set, e.g. for local emulators).
- The JWKS cache never refreshed, so tokens signed after a Cognito key rotation were
  rejected until restart. An unknown `kid` now triggers a new download (at most once a minute).
- The JWKS cache held only one user pool (`maxsize=1`); it is now per URL.
- A failed JWKS download (HTTP error, invalid JSON, missing `keys`) returned or cached
  `None` and led to a `TypeError`; it now raises `CognitoJWTException` and is not cached.
- JWKS downloads had no timeout and could hang forever; the timeout is now 10 seconds.
- Malformed tokens and missing claims (`exp`, `token_use`, `aud`/`client_id`, `kid`)
  raised `ValueError`/`KeyError`/`JWTError`; they now raise `CognitoJWTException`.
- `bytes` tokens were turned into `"b'...'"` and always failed; they are now accepted.
- A local JWKS path starting with `http` (e.g. `httpkeys.json`) was treated as a URL.
- Concurrent `decode_async` calls shared one JWKS download only through `async_lru`;
  this is now built in.

### Changed
- `get_public_key` / `get_public_key_async` return a `joserfc` key instead of a `python-jose` key.
- Requires Python >= 3.8 (required by `joserfc`).
- The `async` extra no longer installs `aiofile` and `async_lru`.
- Tests no longer need a real Cognito user pool; CI runs on GitHub Actions instead of Travis.
