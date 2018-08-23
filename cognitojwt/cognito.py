import logging
import time
from functools import lru_cache
from typing import List

import aiohttp
import requests
from async_lru import alru_cache
from jose import jwk, jwt
from jose.utils import base64url_decode

logger = logging.getLogger(__name__)

PUBLIC_KEYS_URL_TEMPLATE = 'https://cognito-idp.{}.amazonaws.com/{}/.well-known/jwks.json'


class CognitoJWTException(Exception):
    """Raised when something went wrong in token verification proccess"""


@lru_cache(maxsize=1)
def get_keys(keys_url: str) -> List[dict]:
    r = requests.get(keys_url)
    keys_response = r.json()
    keys = keys_response.get('keys')
    return keys


def get_unverified_headers(token: str) -> dict:
    return jwt.get_unverified_headers(token)


def get_unverified_claims(token: str) -> dict:
    return jwt.get_unverified_claims(token)


def get_public_key(token: str, region: str, userpool_id: str):
    keys_url: str = PUBLIC_KEYS_URL_TEMPLATE.format(region, userpool_id)
    keys: list = get_keys(keys_url)
    headers = get_unverified_headers(token)
    kid = headers['kid']

    key = list(filter(lambda k: k['kid'] == kid, keys))
    if not key:
        raise CognitoJWTException('Public key not found in jwks.json')
    else:
        key = key[0]

    return jwk.construct(key)


def decode(token: str, region: str, userpool_id: str, app_client_id: str, testmode=False) -> dict:
    message, encoded_signature = str(token).rsplit('.', 1)

    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

    public_key = get_public_key(token, region, userpool_id)

    if not public_key.verify(message.encode('utf-8'), decoded_signature):
        raise CognitoJWTException('Signature verification failed')

    logger.debug('Signature successfully verified')
    claims = get_unverified_claims(token)

    if time.time() > claims['exp'] and not testmode:
        raise CognitoJWTException('Token is expired')

    if claims['aud'] != app_client_id:
        raise CognitoJWTException('Token was not issued for this client id')

    logger.debug(f'Claims: {claims}')
    return claims


@alru_cache(maxsize=1)
async def get_keys_async(keys_url: str) -> List[dict]:
    async with aiohttp.ClientSession() as session:
        async with session.get(keys_url) as resp:
            response = await resp.json()
            return response.get('keys')


async def get_public_key_async(token: str, region: str, userpool_id: str):
    keys_url: str = PUBLIC_KEYS_URL_TEMPLATE.format(region, userpool_id)
    keys: list = await get_keys_async(keys_url)
    headers = get_unverified_headers(token)
    kid = headers['kid']

    key = list(filter(lambda k: k['kid'] == kid, keys))
    if not key:
        raise CognitoJWTException('Public key not found in jwks.json')
    else:
        key = key[0]

    return jwk.construct(key)


async def decode_async(token: str, region: str, userpool_id: str, app_client_id: str, testmode=False) -> dict:
    message, encoded_signature = str(token).rsplit('.', 1)

    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

    public_key = await get_public_key_async(token, region, userpool_id)

    if not public_key.verify(message.encode('utf-8'), decoded_signature):
        raise CognitoJWTException('Signature verification failed')

    logger.debug('Signature successfully verified')
    claims = get_unverified_claims(token)

    if time.time() > claims['exp'] and not testmode:
        raise CognitoJWTException('Token is expired')

    if claims['aud'] != app_client_id:
        raise CognitoJWTException('Token was not issued for this client id')

    logger.debug(f'Claims: {claims}')
    return claims
