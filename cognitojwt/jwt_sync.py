from typing import Container, List, Optional, Union

import requests
from joserfc.jwk import Key

from . import constants
from ._jwks import (
    JWK, KeysCache, download_error, find_key, get_keys_url, get_kid, is_url, key_not_found,
    parse_jwks, read_jwks_file,
)
from .exceptions import JWKSError
from .token_utils import (
    Claims, ClientIds, Token, verify_claims, verify_signature, warn_if_empty_client_id,
)


_keys_cache = KeysCache()


def _fetch_keys(keys_url: str, timeout: Optional[float] = None) -> List[JWK]:
    if not is_url(keys_url):
        return read_jwks_file(keys_url)
    try:
        response = requests.get(
            keys_url, timeout=constants.HTTP_TIMEOUT if timeout is None else timeout
        )
        response.raise_for_status()
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        raise download_error(keys_url, exc, status) from exc
    except requests.RequestException as exc:
        raise download_error(keys_url, exc) from exc
    return parse_jwks(response.content)


def _get_keys(
        cache: KeysCache, keys_url: str, force_refresh: bool = False, timeout: Optional[float] = None
) -> List[JWK]:
    version = cache.version(keys_url)
    if not force_refresh:
        keys = cache.get_fresh(keys_url)
        if keys is not None:
            return keys
    with cache.download_lock(keys_url):
        if cache.version(keys_url) != version:
            # Another thread downloaded the JWKS while this one was waiting.
            cached = cache.get(keys_url)
            if cached is not None:
                return cached
        recent_failure = cache.recent_failure(keys_url)
        if recent_failure is not None:
            return cache.handle_failure(keys_url, recent_failure, force_refresh)
        try:
            keys = _fetch_keys(keys_url, timeout)
        except JWKSError as exc:
            return cache.handle_failure(keys_url, exc, force_refresh)
        cache.set(keys_url, keys)
        return keys


def get_keys(keys_url: str, force_refresh: bool = False) -> List[JWK]:
    """Return the keys of the JWKS at ``keys_url`` (URL or file path), cached per URL."""
    return _get_keys(_keys_cache, keys_url, force_refresh)


# Backward compatibility: ``get_keys`` used to be wrapped with ``functools.lru_cache``.
get_keys.cache_clear = _keys_cache.clear  # type: ignore[attr-defined]
get_keys.cache_info = _keys_cache.info  # type: ignore[attr-defined]


def _get_public_key(
        cache: KeysCache, token: Token, keys_url: str, timeout: Optional[float] = None
) -> Key:
    kid = get_kid(token)
    keys = _get_keys(cache, keys_url, timeout=timeout)
    key = find_key(keys, kid)
    if key is None and cache.can_refresh(keys_url):
        # The pool keys may have been rotated since they were cached.
        keys = _get_keys(cache, keys_url, force_refresh=True, timeout=timeout)
        key = find_key(keys, kid)
    if key is None:
        raise key_not_found()
    return cache.build_key(keys_url, keys, key)


def get_public_key(token: Token, region: str, userpool_id: str) -> Key:
    """Return the user pool public key the token is signed with (the signature is not verified)."""
    keys_url, _ = get_keys_url(region, userpool_id)
    return _get_public_key(_keys_cache, token, keys_url)


def _verify(
        cache: KeysCache,
        keys_url: str,
        token: Token,
        region: str,
        userpool_id: str,
        app_client_id: Optional[ClientIds],
        testmode: bool,
        verify_issuer: bool,
        *,
        token_use: Optional[Union[str, Container[str]]],
        leeway: float,
        issuer: Optional[str] = None,
        timeout: Optional[float] = None,
) -> Claims:
    public_key = _get_public_key(cache, token, keys_url, timeout)
    claims = verify_signature(token, public_key)
    verify_claims(
        claims, region, userpool_id, app_client_id, testmode, verify_issuer,
        token_use=token_use, leeway=leeway, issuer=issuer,
    )
    return claims


def decode(
        token: Token,
        region: str,
        userpool_id: str,
        app_client_id: Optional[ClientIds] = None,
        testmode: bool = False,
        *,
        token_use: Optional[Union[str, Container[str]]] = None,
        leeway: float = 0,
) -> Claims:
    """Verify a Cognito ID or access token and return its claims.

    :param token: the JWT, ``str`` or ``bytes``.
    :param region: the user pool region, e.g. ``'eu-west-1'``.
    :param userpool_id: the user pool id, e.g. ``'eu-west-1_AbC123'``.
    :param app_client_id: the app client id (or several) the token must be issued
        for: ``aud`` of an ID token, ``client_id`` of an access token. ``None`` skips the check.
    :param testmode: skip the ``exp`` and ``iat`` checks. Never use it in production.
    :param token_use: ``'id'`` or ``'access'`` (or both) to accept only that kind of token.
    :param leeway: seconds of clock skew tolerated for ``exp`` and ``iat``.
    :raises CognitoJWTException: or one of its subclasses, if the token is not valid
        or the user pool keys can't be loaded (:class:`JWKSError`).
    """
    if warn_if_empty_client_id(app_client_id, stacklevel=2):
        app_client_id = None
    keys_url, custom_keys = get_keys_url(region, userpool_id)
    return _verify(
        _keys_cache, keys_url, token, region, userpool_id, app_client_id, testmode,
        # A custom JWKS (e.g. a local emulator) may come with a non-Cognito issuer.
        not custom_keys,
        token_use=token_use, leeway=leeway,
    )


__all__ = [
    'decode'
]
