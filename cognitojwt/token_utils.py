import json
import time
import warnings
from typing import Any, Container, Dict, Optional, Union

from joserfc import jws
from joserfc.errors import BadSignatureError, JoseError
from joserfc.jwk import Key

from . import constants
from .constants import ALLOWED_ALGORITHMS, ISSUER_TEMPLATE
from .exceptions import (
    InvalidClaimError, InvalidSignatureError, MalformedTokenError, TokenExpiredError,
)


Token = Union[str, bytes]
Claims = Dict[str, Any]
ClientIds = Union[str, Container[str]]

CLIENT_ID_KEYS: Dict[str, str] = {
    'access': 'client_id',
    'id': 'aud'
}


def _to_bytes(token: Token) -> bytes:
    if isinstance(token, bytes):
        data = token
    else:
        try:
            data = str(token).encode('ascii')
        except UnicodeEncodeError as exc:
            raise MalformedTokenError('Invalid token: non-ASCII characters') from exc
    # Checked before parsing, so oversized input is never split or decoded.
    if len(data) > constants.MAX_TOKEN_SIZE:
        raise MalformedTokenError('Invalid token: too large')
    return data


def _parse_claims(payload: bytes) -> Claims:
    try:
        claims = json.loads(payload)
    except ValueError as exc:
        raise MalformedTokenError('Invalid token: payload is not valid JSON') from exc
    if not isinstance(claims, dict):
        raise MalformedTokenError('Invalid token: payload is not a JSON object')
    return claims


def _extract(token: Token) -> jws.CompactSignature:
    try:
        return jws.extract_compact(_to_bytes(token))
    # Older joserfc versions raise ValueError for malformed tokens.
    except (JoseError, ValueError) as exc:
        raise MalformedTokenError(f'Invalid token: {exc}') from exc


def get_unverified_headers(token: Token) -> Dict[str, Any]:
    """Return the token header **without** verifying the signature."""
    return dict(_extract(token).headers())


def get_unverified_claims(token: Token) -> Claims:
    """Return the token claims **without** verifying the signature. Don't trust them."""
    return _parse_claims(_extract(token).payload)


def verify_signature(token: Token, public_key: Key) -> Claims:
    """Verify the token signature with ``public_key`` and return its claims."""
    try:
        signature = jws.deserialize_compact(
            _to_bytes(token), public_key, algorithms=list(ALLOWED_ALGORITHMS)
        )
    except BadSignatureError as exc:
        raise InvalidSignatureError('Signature verification failed') from exc
    except (JoseError, ValueError) as exc:
        raise InvalidSignatureError(f'Signature verification failed: {exc}') from exc
    return _parse_claims(signature.payload)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _check_leeway(leeway: float) -> None:
    if not _is_number(leeway) or leeway < 0:
        raise ValueError(f'leeway must be a non-negative number of seconds, not {leeway!r}')


def check_expired(exp: Optional[Union[int, float]], testmode: bool = False, *, leeway: float = 0) -> None:
    """Raise :class:`TokenExpiredError` from ``exp`` (+ ``leeway`` seconds) on."""
    if testmode:
        return
    _check_leeway(leeway)
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise InvalidClaimError('Invalid or missing "exp" claim')
    # RFC 7519: the token must not be accepted on or after "exp".
    if time.time() >= exp + leeway:
        raise TokenExpiredError('Token is expired')


def check_issued_at(iat: Any, *, leeway: float = 0) -> None:
    """Reject an ``iat`` in the future (a missing ``iat`` is allowed).

    ``constants.MAX_IAT_SKEW`` seconds are always tolerated on top of ``leeway``,
    so a server clock that is slightly behind never rejects fresh tokens.
    """
    _check_leeway(leeway)
    if iat is None:
        return
    if not _is_number(iat):
        raise InvalidClaimError('Invalid "iat" claim')
    if iat > time.time() + leeway + constants.MAX_IAT_SKEW:
        raise InvalidClaimError('Token is issued in the future')


def check_issuer(claims: Claims, region: str, userpool_id: str, *, issuer: Optional[str] = None) -> None:
    """Check ``iss``: the user pool URL, or ``issuer`` when it is passed."""
    expected = issuer if issuer is not None else ISSUER_TEMPLATE.format(region, userpool_id)
    if claims.get('iss') != expected:
        raise InvalidClaimError('Token was not issued by this user pool')


def check_token_use(claims: Claims, token_use: Union[str, Container[str]]) -> None:
    """Check that ``token_use`` is the expected one (``'id'`` or ``'access'``)."""
    allowed = (token_use,) if isinstance(token_use, str) else token_use
    actual = claims.get('token_use')
    if not isinstance(actual, str) or actual not in allowed:
        raise InvalidClaimError(f'Invalid token_use: {actual}. Expected: {token_use!r}')


def check_client_id(claims: Claims, app_client_id: ClientIds) -> None:
    """Check ``aud`` (ID token) or ``client_id`` (access token) against ``app_client_id``."""
    token_use = claims.get('token_use')

    client_id_key = CLIENT_ID_KEYS.get(token_use) if isinstance(token_use, str) else None
    if not client_id_key:
        raise InvalidClaimError(f'Invalid token_use: {token_use}. Valid values: {list(CLIENT_ID_KEYS.keys())}')

    if isinstance(app_client_id, str):
        app_client_id = (app_client_id,)

    token_client_id = claims.get(client_id_key)
    # "aud" may legally be a list of audiences (RFC 7519, section 4.1.3).
    candidates = token_client_id if isinstance(token_client_id, list) else [token_client_id]
    if not any(isinstance(c, str) and c in app_client_id for c in candidates):
        raise InvalidClaimError('Token was not issued for this client id audience')


def warn_if_empty_client_id(app_client_id: Optional[ClientIds], stacklevel: int = 1) -> bool:
    """Warn about an empty, but not ``None``, ``app_client_id``; return whether it is."""
    if app_client_id is None or app_client_id:
        return False
    # Usually an unset setting (e.g. an empty environment variable).
    warnings.warn(
        f'app_client_id is empty ({app_client_id!r}), so the token audience is not verified; '
        'pass None to skip the check on purpose',
        stacklevel=stacklevel + 1,
    )
    return True


def verify_claims(
        claims: Claims,
        region: str,
        userpool_id: str,
        app_client_id: Optional[ClientIds] = None,
        testmode: bool = False,
        verify_issuer: bool = True,
        *,
        token_use: Optional[Union[str, Container[str]]] = None,
        leeway: float = 0,
        issuer: Optional[str] = None,
) -> None:
    """Run every claim check; see :func:`cognitojwt.decode` for the parameters."""
    check_expired(claims.get('exp'), testmode=testmode, leeway=leeway)
    if not testmode:
        check_issued_at(claims.get('iat'), leeway=leeway)

    if verify_issuer:
        check_issuer(claims, region, userpool_id, issuer=issuer)

    if token_use is not None:
        check_token_use(claims, token_use)

    if app_client_id:
        check_client_id(claims, app_client_id)
    else:
        warn_if_empty_client_id(app_client_id, stacklevel=2)


__all__ = [
    'check_client_id',
    'check_expired',
    'check_issued_at',
    'check_issuer',
    'check_token_use',
    'get_unverified_claims',
    'get_unverified_headers',
    'verify_claims',
    'verify_signature',
]
