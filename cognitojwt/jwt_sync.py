import json
import os
from functools import lru_cache
from typing import List, Dict, Optional, Union, Container
import requests


from jose import jwk
from jose.utils import base64url_decode

from .constants import PUBLIC_KEYS_URL_TEMPLATE
from .exceptions import CognitoJWTException
from .token_utils import get_unverified_claims, get_unverified_headers, check_expired, check_client_id


@lru_cache(maxsize=1)
def get_keys(keys_url: str) -> List[dict]:
    if keys_url.startswith("http"):
        r = requests.get(keys_url)
        keys_response = r.json()
    else:
        with open(keys_url, "r") as f:
            keys_response = json.loads(f.read())
    return keys_response.get('keys')


def get_public_key(token: str, region: str, userpool_id: str):
    keys_url: str = os.environ.get('AWS_COGNITO_JWKS_PATH') or PUBLIC_KEYS_URL_TEMPLATE.format(region, userpool_id)
    keys: list = get_keys(keys_url)
    headers = get_unverified_headers(token)
    kid = headers['kid']

    key = list(filter(lambda k: k['kid'] == kid, keys))
    if not key:
        raise CognitoJWTException('Public key not found in jwks.json')
    else:
        key = key[0]

    return jwk.construct(key)


def decode(
        token: str,
        region: str,
        userpool_id: str,
        app_client_id: Optional[Union[str, Container[str]]] = None,
        testmode: bool = False
) -> Dict:
    message, encoded_signature = str(token).rsplit('.', 1)

    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))

    public_key = get_public_key(token, region, userpool_id)

    if not public_key.verify(message.encode('utf-8'), decoded_signature):
        raise CognitoJWTException('Signature verification failed')

    claims = get_unverified_claims(token)
    check_expired(claims['exp'], testmode=testmode)

    if app_client_id:
        check_client_id(claims, app_client_id)

    return claims


__all__ = [
    'decode'
]
