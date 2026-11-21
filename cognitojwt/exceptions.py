"""Exceptions raised by cognitojwt.

Every exception is a subclass of :class:`CognitoJWTException`, so
``except CognitoJWTException`` keeps catching all of them. The subclasses tell
a bad token (answer 401) from a problem on the server side (answer 503)::

    try:
        claims = cognitojwt.decode(token, REGION, USERPOOL_ID, APP_CLIENT_ID)
    except cognitojwt.JWKSError:
        ...  # the user pool keys can't be loaded: 503
    except cognitojwt.CognitoJWTException:
        ...  # the token is not valid: 401
"""


class CognitoJWTException(Exception):
    """Raised when something went wrong in token verification process"""


class MalformedTokenError(CognitoJWTException):
    """The token can't be parsed: not a JWS, too large, invalid JSON, no ``kid``."""


class InvalidSignatureError(CognitoJWTException):
    """The signature doesn't match, or the token is signed with an unknown key."""


class TokenExpiredError(CognitoJWTException):
    """The token is expired (``exp`` is in the past)."""


class InvalidClaimError(CognitoJWTException):
    """A claim is missing or has a wrong value: ``exp``, ``iat``, ``iss``,
    ``token_use``, ``aud`` / ``client_id``."""


class InvalidUserPoolError(CognitoJWTException):
    """The region or user pool id passed by the caller is not a valid AWS value."""


class JWKSError(CognitoJWTException):
    """The JWKS can't be downloaded, read or parsed."""


__all__ = [
    'CognitoJWTException',
    'InvalidClaimError',
    'InvalidSignatureError',
    'InvalidUserPoolError',
    'JWKSError',
    'MalformedTokenError',
    'TokenExpiredError',
]
