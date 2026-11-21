# Changelog

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
