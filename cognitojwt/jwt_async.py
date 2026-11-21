import asyncio
from typing import Container, List, Optional, Union

import aiohttp
from joserfc.jwk import Key

from . import constants
from ._jwks import (
    JWK, InFlightKey, KeysCache, download_error, find_key, get_keys_url, get_kid, is_url,
    key_not_found, parse_jwks, read_jwks_file,
)
from .exceptions import JWKSError
from .token_utils import (
    Claims, ClientIds, Token, verify_claims, verify_signature, warn_if_empty_client_id,
)


_keys_cache = KeysCache()
# Downloads in progress, so concurrent requests share one download per URL.
_in_flight = _keys_cache.in_flight


async def _fetch_keys_async(keys_url: str, timeout: Optional[float] = None) -> List[JWK]:
    if not is_url(keys_url):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, read_jwks_file, keys_url)
    client_timeout = aiohttp.ClientTimeout(total=constants.HTTP_TIMEOUT if timeout is None else timeout)
    try:
        async with aiohttp.ClientSession(timeout=client_timeout) as session, session.get(keys_url) as response:
            response.raise_for_status()
            body = await response.read()
    except aiohttp.ClientResponseError as exc:
        raise download_error(keys_url, repr(exc), exc.status) from exc
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        raise download_error(keys_url, repr(exc)) from exc
    return parse_jwks(body)


async def _fetch_and_store(
        cache: KeysCache, keys_url: str, force_refresh: bool, timeout: Optional[float]
) -> List[JWK]:
    recent_failure = cache.recent_failure(keys_url)
    if recent_failure is not None:
        return cache.handle_failure(keys_url, recent_failure, force_refresh)
    try:
        keys = await _fetch_keys_async(keys_url, timeout)
    except JWKSError as exc:
        return cache.handle_failure(keys_url, exc, force_refresh)
    cache.set(keys_url, keys)
    return keys


def _download_done(cache: KeysCache, in_flight_key: InFlightKey, task: 'asyncio.Task[List[JWK]]') -> None:
    cache.in_flight.pop(in_flight_key, None)
    if not task.cancelled():
        # Mark the error as retrieved: if every waiting caller was cancelled, nobody
        # else reads it and asyncio logs "Task exception was never retrieved".
        task.exception()


async def _get_keys_async(
        cache: KeysCache, keys_url: str, force_refresh: bool = False, timeout: Optional[float] = None
) -> List[JWK]:
    if not force_refresh:
        keys = cache.get_fresh(keys_url)
        if keys is not None:
            return keys

    loop = asyncio.get_running_loop()
    in_flight_key = (loop, keys_url)
    task = cache.in_flight.get(in_flight_key)
    if task is None:
        task = loop.create_task(_fetch_and_store(cache, keys_url, force_refresh, timeout))
        cache.in_flight[in_flight_key] = task
        task.add_done_callback(lambda done: _download_done(cache, in_flight_key, done))
    # Shield, so a cancelled caller doesn't cancel the download shared with others.
    return await asyncio.shield(task)


async def get_keys_async(keys_url: str, force_refresh: bool = False) -> List[JWK]:
    """Return the keys of the JWKS at ``keys_url`` (URL or file path), cached per URL."""
    return await _get_keys_async(_keys_cache, keys_url, force_refresh)


# Backward compatibility: ``get_keys_async`` used to be wrapped with ``async_lru.alru_cache``.
get_keys_async.cache_clear = _keys_cache.clear  # type: ignore[attr-defined]
get_keys_async.cache_info = _keys_cache.info  # type: ignore[attr-defined]


async def _get_public_key_async(
        cache: KeysCache, token: Token, keys_url: str, timeout: Optional[float] = None
) -> Key:
    kid = get_kid(token)
    keys = await _get_keys_async(cache, keys_url, timeout=timeout)
    key = find_key(keys, kid)
    if key is None and cache.can_refresh(keys_url):
        # The pool keys may have been rotated since they were cached.
        keys = await _get_keys_async(cache, keys_url, force_refresh=True, timeout=timeout)
        key = find_key(keys, kid)
    if key is None:
        raise key_not_found()
    return cache.build_key(keys_url, keys, key)


async def get_public_key_async(token: Token, region: str, userpool_id: str) -> Key:
    """Return the user pool public key the token is signed with (the signature is not verified)."""
    keys_url, _ = get_keys_url(region, userpool_id)
    return await _get_public_key_async(_keys_cache, token, keys_url)


async def _verify_async(
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
    public_key = await _get_public_key_async(cache, token, keys_url, timeout)
    claims = verify_signature(token, public_key)
    verify_claims(
        claims, region, userpool_id, app_client_id, testmode, verify_issuer,
        token_use=token_use, leeway=leeway, issuer=issuer,
    )
    return claims


async def decode_async(
        token: Token,
        region: str,
        userpool_id: str,
        app_client_id: Optional[ClientIds] = None,
        testmode: bool = False,
        *,
        token_use: Optional[Union[str, Container[str]]] = None,
        leeway: float = 0,
) -> Claims:
    """Async version of :func:`cognitojwt.decode`, with the same parameters."""
    if warn_if_empty_client_id(app_client_id, stacklevel=2):
        app_client_id = None
    keys_url, custom_keys = get_keys_url(region, userpool_id)
    return await _verify_async(
        _keys_cache, keys_url, token, region, userpool_id, app_client_id, testmode,
        # A custom JWKS (e.g. a local emulator) may come with a non-Cognito issuer.
        not custom_keys,
        token_use=token_use, leeway=leeway,
    )


__all__ = [
    'decode_async'
]
