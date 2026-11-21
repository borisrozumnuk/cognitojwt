from typing import Container, Dict, List, Optional, Union

import requests
from joserfc.jwk import Key

from . import constants
from ._jwks import (
    KEY_NOT_FOUND_MESSAGE, KeysCache, construct_key, find_key, get_keys_url, get_kid,
    is_url, parse_jwks, read_jwks_file,
)
from .exceptions import CognitoJWTException
from .token_utils import Token, verify_claims, verify_signature


_keys_cache = KeysCache()


def _fetch_keys(keys_url: str) -> List[dict]:
    if not is_url(keys_url):
        return read_jwks_file(keys_url)
    try:
        response = requests.get(keys_url, timeout=constants.HTTP_TIMEOUT)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise CognitoJWTException(f'Unable to download JWKS from {keys_url}: {exc}') from exc
    return parse_jwks(response.content)


def get_keys(keys_url: str, force_refresh: bool = False) -> List[dict]:
    """Return the keys of the JWKS at ``keys_url`` (URL or file path), cached per URL."""
    if not force_refresh:
        keys = _keys_cache.get(keys_url)
        if keys is not None:
            return keys
    keys = _fetch_keys(keys_url)
    _keys_cache.set(keys_url, keys)
    return keys


# Backward compatibility: ``get_keys`` used to be wrapped with ``functools.lru_cache``.
get_keys.cache_clear = _keys_cache.clear  # type: ignore[attr-defined]


def _get_public_key(token: Token, keys_url: str) -> Key:
    kid = get_kid(token)
    key = find_key(get_keys(keys_url), kid)
    if key is None and _keys_cache.can_refresh(keys_url):
        # The pool keys may have been rotated since they were cached.
        key = find_key(get_keys(keys_url, force_refresh=True), kid)
    if key is None:
        raise CognitoJWTException(KEY_NOT_FOUND_MESSAGE)
    return construct_key(key)


def get_public_key(token: Token, region: str, userpool_id: str) -> Key:
    keys_url, _ = get_keys_url(region, userpool_id)
    return _get_public_key(token, keys_url)


def decode(
        token: Token,
        region: str,
        userpool_id: str,
        app_client_id: Optional[Union[str, Container[str]]] = None,
        testmode: bool = False
) -> Dict:
    keys_url, custom_keys = get_keys_url(region, userpool_id)
    public_key = _get_public_key(token, keys_url)
    claims = verify_signature(token, public_key)
    verify_claims(
        claims,
        region,
        userpool_id,
        app_client_id=app_client_id,
        testmode=testmode,
        # A custom JWKS (e.g. a local emulator) may come with a non-Cognito issuer.
        verify_issuer=not custom_keys,
    )
    return claims


__all__ = [
    'decode'
]
