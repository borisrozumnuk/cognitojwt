"""JWKS helpers shared by the sync and async implementations (internal)."""
import json
import os
import time
from typing import Dict, List, Optional, Tuple, Union

from joserfc import jwk
from joserfc.errors import JoseError

from . import constants
from .exceptions import CognitoJWTException
from .token_utils import Token, get_unverified_headers


def get_keys_url(region: str, userpool_id: str) -> Tuple[str, bool]:
    """Return ``(keys_url, is_custom)``; custom means overridden via the environment."""
    custom = os.environ.get(constants.JWKS_PATH_ENV)
    if custom:
        return custom, True
    return constants.PUBLIC_KEYS_URL_TEMPLATE.format(region, userpool_id), False


def is_url(keys_url: str) -> bool:
    return keys_url.lower().startswith(('http://', 'https://'))


def parse_jwks(data: Union[str, bytes]) -> List[dict]:
    try:
        jwks = json.loads(data)
    except ValueError as exc:
        raise CognitoJWTException('Invalid JWKS: not valid JSON') from exc
    keys = jwks.get('keys') if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        raise CognitoJWTException('Invalid JWKS: "keys" list is missing')
    return keys


def read_jwks_file(path: str) -> List[dict]:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = f.read()
    except OSError as exc:
        raise CognitoJWTException(f'Unable to read JWKS file {path!r}: {exc}') from exc
    return parse_jwks(data)


def get_kid(token: Token) -> str:
    kid = get_unverified_headers(token).get('kid')
    if not kid or not isinstance(kid, str):
        raise CognitoJWTException('Token header has no "kid"')
    return kid


def find_key(keys: List[dict], kid: str) -> Optional[dict]:
    for key in keys:
        if isinstance(key, dict) and key.get('kid') == kid:
            return key
    return None


def construct_key(key: dict) -> jwk.Key:
    try:
        return jwk.JWKRegistry.import_key(key)
    except (JoseError, ValueError, TypeError) as exc:
        raise CognitoJWTException(f'Invalid public key in jwks.json: {exc}') from exc


KEY_NOT_FOUND_MESSAGE = 'Public key not found in jwks.json'


class KeysCache:
    """Per-URL JWKS cache that remembers when each entry was fetched."""

    def __init__(self) -> None:
        self._entries: Dict[str, Tuple[float, List[dict]]] = {}

    def get(self, keys_url: str) -> Optional[List[dict]]:
        entry = self._entries.get(keys_url)
        return entry[1] if entry else None

    def set(self, keys_url: str, keys: List[dict]) -> None:
        self._entries[keys_url] = (time.monotonic(), keys)

    def can_refresh(self, keys_url: str) -> bool:
        entry = self._entries.get(keys_url)
        return entry is None or time.monotonic() - entry[0] >= constants.KEYS_REFRESH_INTERVAL

    def clear(self) -> None:
        self._entries.clear()
