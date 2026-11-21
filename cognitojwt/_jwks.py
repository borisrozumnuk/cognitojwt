"""JWKS helpers shared by the sync and async implementations (internal)."""
import asyncio
import json
import logging
import os
import re
import threading
import time
import warnings
import weakref
from collections import OrderedDict
from typing import Any, Dict, List, NamedTuple, Optional, Tuple, Union
from urllib.parse import urlsplit

from joserfc import jwk
from joserfc.errors import JoseError

from . import constants
from .exceptions import InvalidSignatureError, InvalidUserPoolError, JWKSError, MalformedTokenError
from .token_utils import Token, get_unverified_headers


JWK = Dict[str, Any]

logger = logging.getLogger('cognitojwt')

# AWS region names (e.g. "eu-west-1", "us-gov-west-1") and user pool ids
# ("<region>_<id>"). Only these characters may end up in the JWKS URL.
_REGION_RE = re.compile(r'[a-z]+(-[a-z]+)+-[0-9]+', re.ASCII)
_USERPOOL_ID_RE = re.compile(r'[\w-]+_[0-9a-zA-Z]+', re.ASCII)

_LOCAL_HOSTS = ('localhost', '127.0.0.1', '::1')


def validate_pool(region: str, userpool_id: str) -> None:
    """Reject values that would change the host or path of the Cognito JWKS URL."""
    if not isinstance(region, str) or not _REGION_RE.fullmatch(region):
        raise InvalidUserPoolError(f'Invalid region: {region!r}')
    if (
        not isinstance(userpool_id, str)
        or not _USERPOOL_ID_RE.fullmatch(userpool_id)
        or userpool_id.split('_', 1)[0] != region
    ):
        raise InvalidUserPoolError(f'Invalid user pool id for region {region}: {userpool_id!r}')


def warn_if_insecure(keys_url: str, stacklevel: int = 4) -> None:
    parts = urlsplit(keys_url)
    if parts.scheme.lower() != 'http':
        return
    host = (parts.hostname or '').lower()
    if host in _LOCAL_HOSTS or host.endswith('.localhost'):
        return
    warnings.warn(
        f'The JWKS is downloaded over plain HTTP ({keys_url}), so it can be tampered with '
        'in transit; use HTTPS',
        stacklevel=stacklevel,
    )


def get_keys_url(region: str, userpool_id: str) -> Tuple[str, bool]:
    """Return ``(keys_url, is_custom)``; custom means overridden via the environment."""
    custom = os.environ.get(constants.JWKS_PATH_ENV)
    if custom:
        # Emulators may use any region / pool id, so they are not validated here.
        warn_if_insecure(custom)
        return custom, True
    validate_pool(region, userpool_id)
    return constants.PUBLIC_KEYS_URL_TEMPLATE.format(region, userpool_id), False


def is_url(keys_url: str) -> bool:
    return keys_url.lower().startswith(('http://', 'https://'))


def parse_jwks(data: Union[str, bytes]) -> List[JWK]:
    try:
        jwks = json.loads(data)
    except ValueError as exc:
        raise JWKSError('Invalid JWKS: not valid JSON') from exc
    keys = jwks.get('keys') if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        raise JWKSError('Invalid JWKS: "keys" list is missing')
    return keys


def read_jwks_file(path: str) -> List[JWK]:
    try:
        with open(path, encoding='utf-8') as f:
            data = f.read()
    except OSError as exc:
        raise JWKSError(f'Unable to read JWKS file {path!r}: {exc}') from exc
    return parse_jwks(data)


def get_kid(token: Token) -> str:
    kid = get_unverified_headers(token).get('kid')
    if not kid or not isinstance(kid, str):
        raise MalformedTokenError('Token header has no "kid"')
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
        raise JWKSError(f'Invalid public key in jwks.json: {exc}') from exc


KEY_NOT_FOUND_MESSAGE = 'Public key not found in jwks.json'


def key_not_found() -> InvalidSignatureError:
    return InvalidSignatureError(KEY_NOT_FOUND_MESSAGE)


class _ClientError(JWKSError):
    """A 4xx answer, e.g. for a user pool that doesn't exist: retrying right away won't help."""


def download_error(keys_url: str, reason: object, status: Optional[int] = None) -> JWKSError:
    """Build the error for a failed download; a 4xx answer is remembered for a while."""
    permanent = status is not None and 400 <= status < 500 and status not in (408, 429)
    cls = _ClientError if permanent else JWKSError
    return cls(f'Unable to download JWKS from {keys_url}: {reason}')


class CacheInfo(NamedTuple):
    """Same fields as ``functools.lru_cache().cache_info()``."""

    hits: int
    misses: int
    maxsize: int
    currsize: int


class _DownloadLock:
    __slots__ = ('__weakref__', 'lock')

    def __init__(self) -> None:
        self.lock = threading.Lock()


class _Entry:
    __slots__ = ('fetched_at', 'keys', 'parsed', 'retry_at', 'version')

    def __init__(self, keys: List[JWK], version: int) -> None:
        self.keys = keys
        self.version = version
        self.fetched_at = time.monotonic()
        # Set after a failed refresh: the keys are used until then, even if expired.
        self.retry_at = 0.0
        # kid -> key object built from ``keys``, so it isn't rebuilt on every call.
        self.parsed: Dict[str, jwk.Key] = {}


InFlightKey = Tuple[asyncio.AbstractEventLoop, str]


class KeysCache:
    """Per-URL JWKS cache shared by the sync and async code paths.

    * entries expire after ``constants.KEYS_MAX_AGE``; if the new download fails,
      the old keys keep being used and the download is retried later;
    * at most ``constants.KEYS_CACHE_SIZE`` URLs are kept (least recently used dropped);
    * a 4xx answer is remembered for ``constants.KEYS_REFRESH_INTERVAL``;
    * concurrent downloads of one URL are shared (a lock for threads, a task for asyncio).
    """

    def __init__(self) -> None:
        self._entries: OrderedDict[str, _Entry] = OrderedDict()
        # url -> (remembered until, error message)
        self._failures: OrderedDict[str, Tuple[float, str]] = OrderedDict()
        self._version = 0
        self._lock = threading.RLock()
        self._download_locks: weakref.WeakValueDictionary[str, _DownloadLock] = weakref.WeakValueDictionary()
        # Downloads in progress in each event loop.
        self.in_flight: Dict[InFlightKey, asyncio.Task[List[JWK]]] = {}
        self._hits = 0
        self._misses = 0

    def get(self, keys_url: str) -> Optional[List[JWK]]:
        """The cached keys, however old they are."""
        with self._lock:
            entry = self._entries.get(keys_url)
            return entry.keys if entry else None

    def get_fresh(self, keys_url: str) -> Optional[List[JWK]]:
        """The cached keys, unless they are expired and should be downloaded again."""
        with self._lock:
            entry = self._entries.get(keys_url)
            if entry is None:
                return None
            now = time.monotonic()
            if now - entry.fetched_at >= constants.KEYS_MAX_AGE and now >= entry.retry_at:
                return None
            self._entries.move_to_end(keys_url)
            self._hits += 1
            return entry.keys

    def set(self, keys_url: str, keys: List[JWK]) -> None:
        with self._lock:
            self._version += 1
            self._misses += 1
            self._entries[keys_url] = _Entry(keys, self._version)
            self._entries.move_to_end(keys_url)
            self._failures.pop(keys_url, None)
            while len(self._entries) > max(constants.KEYS_CACHE_SIZE, 1):
                self._entries.popitem(last=False)

    def version(self, keys_url: str) -> int:
        """A number that changes every time the entry for ``keys_url`` is stored."""
        with self._lock:
            entry = self._entries.get(keys_url)
            return entry.version if entry else 0

    def can_refresh(self, keys_url: str) -> bool:
        """Whether an unknown ``kid`` may trigger a new download (key rotation)."""
        with self._lock:
            entry = self._entries.get(keys_url)
            if entry is None:
                return True
            now = time.monotonic()
            return now - entry.fetched_at >= constants.KEYS_REFRESH_INTERVAL and now >= entry.retry_at

    def build_key(self, keys_url: str, keys: List[JWK], key: JWK) -> jwk.Key:
        """``construct_key(key)``, cached while ``keys`` is the cached JWKS."""
        kid = key.get('kid')
        if not isinstance(kid, str):
            return construct_key(key)
        with self._lock:
            entry = self._entries.get(keys_url)
            if entry is None or entry.keys is not keys:
                entry = None
            elif kid in entry.parsed:
                return entry.parsed[kid]
        built = construct_key(key)
        if entry is not None:
            with self._lock:
                entry.parsed[kid] = built
        return built

    def download_lock(self, keys_url: str) -> '_HeldLock':
        """A lock per URL; it is forgotten once no thread holds it."""
        with self._lock:
            holder = self._download_locks.get(keys_url)
            if holder is None:
                holder = self._download_locks[keys_url] = _DownloadLock()
        # Keep the holder alive while the caller uses the lock.
        return _HeldLock(holder)

    def recent_failure(self, keys_url: str) -> Optional[JWKSError]:
        """The remembered 4xx error for ``keys_url``, if it is recent."""
        with self._lock:
            failure = self._failures.get(keys_url)
            if failure is None:
                return None
            if time.monotonic() >= failure[0]:
                del self._failures[keys_url]
                return None
            return JWKSError(failure[1])

    def handle_failure(self, keys_url: str, error: JWKSError, force_refresh: bool) -> List[JWK]:
        """Return the old keys after a failed download (stale-if-error), or raise ``error``."""
        with self._lock:
            if isinstance(error, _ClientError):
                self._failures[keys_url] = (time.monotonic() + constants.KEYS_REFRESH_INTERVAL, str(error))
                self._failures.move_to_end(keys_url)
                while len(self._failures) > max(constants.KEYS_CACHE_SIZE, 1):
                    self._failures.popitem(last=False)
            entry = self._entries.get(keys_url)
            if entry is not None:
                # Don't retry on every request while the endpoint is failing.
                entry.retry_at = time.monotonic() + constants.KEYS_REFRESH_INTERVAL
        if entry is None or force_refresh:
            raise error
        logger.warning('Using the cached JWKS for %s, refreshing it failed: %s', keys_url, error)
        return entry.keys

    def info(self) -> CacheInfo:
        with self._lock:
            return CacheInfo(self._hits, self._misses, constants.KEYS_CACHE_SIZE, len(self._entries))

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._failures.clear()
            self._hits = self._misses = 0


class _HeldLock:
    """Context manager over a :class:`_DownloadLock` that keeps it referenced."""

    __slots__ = ('_holder',)

    def __init__(self, holder: _DownloadLock) -> None:
        self._holder = holder

    def __enter__(self) -> None:
        self._holder.lock.acquire()

    def __exit__(self, *exc_info: object) -> None:
        self._holder.lock.release()
