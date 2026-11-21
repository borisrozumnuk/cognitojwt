import asyncio
from typing import Container, Dict, List, Optional, Tuple, Union

import aiohttp
from joserfc.jwk import Key

from . import constants
from ._jwks import (
    JWK, KEY_NOT_FOUND_MESSAGE, KeysCache, construct_key, find_key, get_keys_url, get_kid,
    is_url, parse_jwks, read_jwks_file,
)
from .exceptions import CognitoJWTException
from .token_utils import Claims, Token, verify_claims, verify_signature


_keys_cache = KeysCache()
# Downloads in progress, so concurrent requests share one download per URL.
_in_flight: Dict[Tuple[asyncio.AbstractEventLoop, str], 'asyncio.Task[List[JWK]]'] = {}


async def _fetch_keys_async(keys_url: str) -> List[JWK]:
    if not is_url(keys_url):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, read_jwks_file, keys_url)
    timeout = aiohttp.ClientTimeout(total=constants.HTTP_TIMEOUT)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session, session.get(keys_url) as response:
            response.raise_for_status()
            body = await response.read()
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        raise CognitoJWTException(f'Unable to download JWKS from {keys_url}: {exc!r}') from exc
    return parse_jwks(body)


async def _fetch_and_store(keys_url: str) -> List[JWK]:
    keys = await _fetch_keys_async(keys_url)
    _keys_cache.set(keys_url, keys)
    return keys


def _download_done(in_flight_key: Tuple[asyncio.AbstractEventLoop, str], task: 'asyncio.Task[List[JWK]]') -> None:
    _in_flight.pop(in_flight_key, None)
    if not task.cancelled():
        # Mark the error as retrieved: if every waiting caller was cancelled, nobody
        # else reads it and asyncio logs "Task exception was never retrieved".
        task.exception()


async def get_keys_async(keys_url: str, force_refresh: bool = False) -> List[JWK]:
    """Return the keys of the JWKS at ``keys_url`` (URL or file path), cached per URL."""
    if not force_refresh:
        keys = _keys_cache.get(keys_url)
        if keys is not None:
            return keys

    loop = asyncio.get_running_loop()
    in_flight_key = (loop, keys_url)
    task = _in_flight.get(in_flight_key)
    if task is None:
        task = loop.create_task(_fetch_and_store(keys_url))
        _in_flight[in_flight_key] = task
        task.add_done_callback(lambda done: _download_done(in_flight_key, done))
    # Shield, so a cancelled caller doesn't cancel the download shared with others.
    return await asyncio.shield(task)


# Backward compatibility: ``get_keys_async`` used to be wrapped with ``async_lru.alru_cache``.
get_keys_async.cache_clear = _keys_cache.clear  # type: ignore[attr-defined]


async def _get_public_key_async(token: Token, keys_url: str) -> Key:
    kid = get_kid(token)
    key = find_key(await get_keys_async(keys_url), kid)
    if key is None and _keys_cache.can_refresh(keys_url):
        # The pool keys may have been rotated since they were cached.
        key = find_key(await get_keys_async(keys_url, force_refresh=True), kid)
    if key is None:
        raise CognitoJWTException(KEY_NOT_FOUND_MESSAGE)
    return construct_key(key)


async def get_public_key_async(token: Token, region: str, userpool_id: str) -> Key:
    keys_url, _ = get_keys_url(region, userpool_id)
    return await _get_public_key_async(token, keys_url)


async def decode_async(
        token: Token,
        region: str,
        userpool_id: str,
        app_client_id: Optional[Union[str, Container[str]]] = None,
        testmode: bool = False
) -> Claims:
    keys_url, custom_keys = get_keys_url(region, userpool_id)
    public_key = await _get_public_key_async(token, keys_url)
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
    'decode_async'
]
