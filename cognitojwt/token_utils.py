import json
import time
from typing import Any, Container, Dict, Optional, Union

from joserfc import jws
from joserfc.errors import BadSignatureError, JoseError
from joserfc.jwk import Key

from .constants import ALLOWED_ALGORITHMS, ISSUER_TEMPLATE
from .exceptions import CognitoJWTException


Token = Union[str, bytes]

CLIENT_ID_KEYS: Dict[str, str] = {
    'access': 'client_id',
    'id': 'aud'
}


def _to_bytes(token: Token) -> bytes:
    if isinstance(token, bytes):
        return token
    try:
        return str(token).encode('ascii')
    except UnicodeEncodeError as exc:
        raise CognitoJWTException('Invalid token: non-ASCII characters') from exc


def _parse_claims(payload: bytes) -> Dict[str, Any]:
    try:
        claims = json.loads(payload)
    except ValueError as exc:
        raise CognitoJWTException('Invalid token: payload is not valid JSON') from exc
    if not isinstance(claims, dict):
        raise CognitoJWTException('Invalid token: payload is not a JSON object')
    return claims


def _extract(token: Token) -> jws.CompactSignature:
    try:
        return jws.extract_compact(_to_bytes(token))
    # Older joserfc versions raise ValueError for malformed tokens.
    except (JoseError, ValueError) as exc:
        raise CognitoJWTException(f'Invalid token: {exc}') from exc


def get_unverified_headers(token: Token) -> dict:
    return dict(_extract(token).headers())


def get_unverified_claims(token: Token) -> dict:
    return _parse_claims(_extract(token).payload)


def verify_signature(token: Token, public_key: Key) -> Dict[str, Any]:
    """Verify the token signature with ``public_key`` and return its claims."""
    try:
        signature = jws.deserialize_compact(
            _to_bytes(token), public_key, algorithms=list(ALLOWED_ALGORITHMS)
        )
    except BadSignatureError as exc:
        raise CognitoJWTException('Signature verification failed') from exc
    except (JoseError, ValueError) as exc:
        raise CognitoJWTException(f'Signature verification failed: {exc}') from exc
    return _parse_claims(signature.payload)


def check_expired(exp: Optional[Union[int, float]], testmode: bool = False) -> None:
    if testmode:
        return
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise CognitoJWTException('Invalid or missing "exp" claim')
    if time.time() > exp:
        raise CognitoJWTException('Token is expired')


def check_issuer(claims: Dict, region: str, userpool_id: str) -> None:
    if claims.get('iss') != ISSUER_TEMPLATE.format(region, userpool_id):
        raise CognitoJWTException('Token was not issued by this user pool')


def check_client_id(claims: Dict, app_client_id: Union[str, Container[str]]) -> None:
    token_use = claims.get('token_use')

    client_id_key = CLIENT_ID_KEYS.get(token_use) if isinstance(token_use, str) else None
    if not client_id_key:
        raise CognitoJWTException(f'Invalid token_use: {token_use}. Valid values: {list(CLIENT_ID_KEYS.keys())}')

    if isinstance(app_client_id, str):
        app_client_id = (app_client_id,)

    token_client_id = claims.get(client_id_key)
    # "aud" may legally be a list of audiences (RFC 7519, section 4.1.3).
    candidates = token_client_id if isinstance(token_client_id, list) else [token_client_id]
    if not any(isinstance(c, str) and c in app_client_id for c in candidates):
        raise CognitoJWTException('Token was not issued for this client id audience')


def verify_claims(
        claims: Dict,
        region: str,
        userpool_id: str,
        app_client_id: Optional[Union[str, Container[str]]] = None,
        testmode: bool = False,
        verify_issuer: bool = True
) -> None:
    check_expired(claims.get('exp'), testmode=testmode)

    if verify_issuer:
        check_issuer(claims, region, userpool_id)

    if app_client_id:
        check_client_id(claims, app_client_id)


__all__ = [
    'get_unverified_headers',
    'get_unverified_claims',
    'verify_signature',
    'check_expired',
    'check_issuer',
    'check_client_id',
    'verify_claims',
]
