import time

from jose import jwt

from .exceptions import CognitoJWTException


def get_unverified_headers(token: str) -> dict:
    return jwt.get_unverified_headers(token)


def get_unverified_claims(token: str) -> dict:
    return jwt.get_unverified_claims(token)


def check_expired(exp: int, testmode: bool = False) -> None:
    if time.time() > exp and not testmode:
        raise CognitoJWTException('Token is expired')


def check_aud(aud: str, app_client_id: str) -> None:
    if aud != app_client_id:
        raise CognitoJWTException('Token was not issued for this client id')
