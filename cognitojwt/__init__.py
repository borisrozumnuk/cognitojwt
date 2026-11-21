from importlib.util import find_spec

from .exceptions import CognitoJWTException

name = 'cognitojwt'
__version__ = '1.6.1'

__all__ = ['CognitoJWTException']

# ``decode`` / ``decode_async`` are available only when the matching extra
# (``cognitojwt[sync]`` / ``cognitojwt[async]``) is installed. Errors other than
# a missing HTTP client are not swallowed, so a broken install fails loudly.
if find_spec('requests') is not None:
    from .jwt_sync import decode as decode
    __all__.append('decode')

if find_spec('aiohttp') is not None:
    from .jwt_async import decode_async as decode_async
    __all__.append('decode_async')
