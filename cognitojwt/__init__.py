from importlib.util import find_spec

from .exceptions import (
    CognitoJWTException, InvalidClaimError, InvalidSignatureError, InvalidUserPoolError, JWKSError,
    MalformedTokenError, TokenExpiredError,
)
from .verifier import CognitoJWTVerifier

name = 'cognitojwt'
__version__ = '1.7.0'

__all__ = [
    'CognitoJWTException',
    'CognitoJWTVerifier',
    'InvalidClaimError',
    'InvalidSignatureError',
    'InvalidUserPoolError',
    'JWKSError',
    'MalformedTokenError',
    'TokenExpiredError',
]

if find_spec('requests') is not None:
    from .jwt_sync import decode as decode
    __all__.append('decode')

if find_spec('aiohttp') is not None:
    from .jwt_async import decode_async as decode_async
    __all__.append('decode_async')
