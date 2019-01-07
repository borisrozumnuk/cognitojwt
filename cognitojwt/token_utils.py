import time

from typing import Dict
from jose import jwt

from .exceptions import CognitoJWTException


def get_unverified_headers(token: str) -> dict:
    return jwt.get_unverified_headers(token)


def get_unverified_claims(token: str) -> dict:
    return jwt.get_unverified_claims(token)


def check_expired(exp: int, testmode: bool = False) -> None:
    if time.time() > exp and not testmode:
        raise CognitoJWTException('Token is expired')


def check_client_id(claims: Dict, app_client_id: str) -> None:
    token_use = claims['token_use']

    if token_use == 'access':
        if claims['aud'] != app_client_id:
            raise CognitoJWTException('Token was not issued for this client id audience')
    elif token_use == 'id':
        if claims['client_id'] != app_client_id:
            raise CognitoJWTException('Token was not issued for this client id')



__all__ = [
    'get_unverified_headers',
    'get_unverified_claims',
    'check_expired',
    'check_aud'
]
