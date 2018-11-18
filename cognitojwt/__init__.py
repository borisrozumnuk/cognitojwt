from .async import decode_async
from .cognito import decode
from .exceptions import CognitoJWTException

name = "cognitojwt"

PUBLIC_KEYS_URL_TEMPLATE = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'


__all__ = [
    'CognitoJWTException',
    'decode',
    'decode_async'
]
