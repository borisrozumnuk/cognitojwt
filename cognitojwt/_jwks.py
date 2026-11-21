"""JWKS helpers shared by the sync and async implementations (internal)."""
import json
import os
import re
import time
import warnings
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlsplit

from joserfc import jwk
from joserfc.errors import JoseError

from . import constants
from .exceptions import CognitoJWTException
from .token_utils import Token, get_unverified_headers


JWK = Dict[str, Any]

# AWS region names (e.g. "eu-west-1", "us-gov-west-1") and user pool ids
# ("<region>_<id>"). Only these characters may end up in the JWKS URL.
_REGION_RE = re.compile(r'[a-z]+(-[a-z]+)+-[0-9]+', re.ASCII)
_USERPOOL_ID_RE = re.compile(r'[\w-]+_[0-9a-zA-Z]+', re.ASCII)

_LOCAL_HOSTS = ('localhost', '127.0.0.1', '::1')


def validate_pool(region: str, userpool_id: str) -> None:
    """Reject values that would change the host or path of the Cognito JWKS URL."""
    if not isinstance(region, str) or not _REGION_RE.fullmatch(region):
        raise CognitoJWTException(f'Invalid region: {region!r}')
    if (
        not isinstance(userpool_id, str)
        or not _USERPOOL_ID_RE.fullmatch(userpool_id)
        or userpool_id.split('_', 1)[0] != region
    ):
        raise CognitoJWTException(f'Invalid user pool id for region {region}: {userpool_id!r}')


def _warn_if_insecure(keys_url: str) -> None:
    parts = urlsplit(keys_url)
    if parts.scheme.lower() != 'http':
        return
    host = (parts.hostname or '').lower()
    if host in _LOCAL_HOSTS or host.endswith('.localhost'):
        return
    warnings.warn(
        f'The JWKS is downloaded over plain HTTP ({keys_url}), so it can be tampered with '
        'in transit; use HTTPS',
        stacklevel=4,
    )


def get_keys_url(region: str, userpool_id: str) -> Tuple[str, bool]:
    """Return ``(keys_url, is_custom)``; custom means overridden via the environment."""
    custom = os.environ.get(constants.JWKS_PATH_ENV)
    if custom:
        # Emulators may use any region / pool id, so they are not validated here.
        _warn_if_insecure(custom)
        return custom, True
    validate_pool(region, userpool_id)
    return constants.PUBLIC_KEYS_URL_TEMPLATE.format(region, userpool_id), False


def is_url(keys_url: str) -> bool:
    return keys_url.lower().startswith(('http://', 'https://'))


def parse_jwks(data: Union[str, bytes]) -> List[JWK]:
    try:
        jwks = json.loads(data)
    except ValueError as exc:
        raise CognitoJWTException('Invalid JWKS: not valid JSON') from exc
    keys = jwks.get('keys') if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        raise CognitoJWTException('Invalid JWKS: "keys" list is missing')
    return keys


def read_jwks_file(path: str) -> List[JWK]:
    try:
        with open(path, encoding='utf-8') as f:
            data = f.read()
    except OSError as exc:
        raise CognitoJWTException(f'Unable to read JWKS file {path!r}: {exc}') from exc
    return parse_jwks(data)


def get_kid(token: Token) -> str:
    kid = get_unverified_headers(token).get('kid')
    if not kid or not isinstance(kid, str):
        raise CognitoJWTException('Token header has no "kid"')
    return kid


def find_key(keys: List[JWK], kid: str) -> Optional[JWK]:
    for key in keys:
        if isinstance(key, dict) and key.get('kid') == kid:
            return key
    return None


def construct_key(key: JWK) -> jwk.Key:
    try:
        return jwk.JWKRegistry.import_key(key)
    except (JoseError, ValueError, TypeError) as exc:
        raise CognitoJWTException(f'Invalid public key in jwks.json: {exc}') from exc


KEY_NOT_FOUND_MESSAGE = 'Public key not found in jwks.json'


class KeysCache:
    """Per-URL JWKS cache that remembers when each entry was fetched."""

    def __init__(self) -> None:
        # url -> (fetched at, keys, version)
        self._entries: Dict[str, Tuple[float, List[JWK], int]] = {}
        self._version = 0

    def get(self, keys_url: str) -> Optional[List[JWK]]:
        entry = self._entries.get(keys_url)
        return entry[1] if entry else None

    def set(self, keys_url: str, keys: List[JWK]) -> None:
        self._version += 1
        self._entries[keys_url] = (time.monotonic(), keys, self._version)

    def version(self, keys_url: str) -> int:
        """A number that changes every time the entry for ``keys_url`` is stored."""
        entry = self._entries.get(keys_url)
        return entry[2] if entry else 0

    def can_refresh(self, keys_url: str) -> bool:
        entry = self._entries.get(keys_url)
        return entry is None or time.monotonic() - entry[0] >= constants.KEYS_REFRESH_INTERVAL

    def clear(self) -> None:
        self._entries.clear()
