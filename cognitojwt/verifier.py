from typing import Container, Optional, Union

from ._jwks import KeysCache, get_keys_url, warn_if_insecure
from .token_utils import Claims, ClientIds, Token, _check_leeway, warn_if_empty_client_id


class CognitoJWTVerifier:
    """Verifies tokens of one user pool with a fixed configuration and its own key cache.

    ::

        verifier = CognitoJWTVerifier(REGION, USERPOOL_ID, APP_CLIENT_ID, token_use='access')
        claims = verifier.verify(token)               # needs the "sync" extra
        claims = await verifier.verify_async(token)   # needs the "async" extra

    :param region: the user pool region, e.g. ``'eu-west-1'``.
    :param userpool_id: the user pool id, e.g. ``'eu-west-1_AbC123'``.
    :param app_client_id: the app client id (or several) the token must be issued for.
        ``None`` skips the check.
    :param token_use: ``'id'`` or ``'access'`` (or both) to accept only that kind of token.
    :param leeway: seconds of clock skew tolerated for ``exp`` and ``iat``.
    :param jwks_url: URL or file path of the JWKS, e.g. of a local emulator. Defaults to
        ``AWS_COGNITO_JWKS_PATH`` (read once, here) or else the user pool JWKS.
    :param issuer: the expected ``iss``. Defaults to the user pool URL; not checked when
        the JWKS is not the user pool one (``jwks_url`` or ``AWS_COGNITO_JWKS_PATH``),
        unless it is passed.
    :param timeout: timeout in seconds for downloading the JWKS (default 10).
    """

    def __init__(
            self,
            region: str,
            userpool_id: str,
            app_client_id: Optional[ClientIds] = None,
            *,
            token_use: Optional[Union[str, Container[str]]] = None,
            leeway: float = 0,
            jwks_url: Optional[str] = None,
            issuer: Optional[str] = None,
            timeout: Optional[float] = None,
    ) -> None:
        _check_leeway(leeway)
        if warn_if_empty_client_id(app_client_id, stacklevel=2):
            app_client_id = None
        if jwks_url:
            warn_if_insecure(jwks_url, stacklevel=3)
            keys_url, custom_keys = jwks_url, True
        else:
            keys_url, custom_keys = get_keys_url(region, userpool_id)

        self.region = region
        self.userpool_id = userpool_id
        self.app_client_id = app_client_id
        self.token_use = token_use
        self.leeway = leeway
        self.jwks_url = keys_url
        self.issuer = issuer
        self.timeout = timeout
        self._verify_issuer = issuer is not None or not custom_keys
        self._cache = KeysCache()

    def verify(self, token: Token, *, testmode: bool = False) -> Claims:
        """Verify the token and return its claims (see :func:`cognitojwt.decode`)."""
        from .jwt_sync import _verify

        return _verify(
            self._cache, self.jwks_url, token, self.region, self.userpool_id,
            self.app_client_id, testmode, self._verify_issuer,
            token_use=self.token_use, leeway=self.leeway, issuer=self.issuer, timeout=self.timeout,
        )

    async def verify_async(self, token: Token, *, testmode: bool = False) -> Claims:
        """Async version of :meth:`verify`."""
        from .jwt_async import _verify_async

        return await _verify_async(
            self._cache, self.jwks_url, token, self.region, self.userpool_id,
            self.app_client_id, testmode, self._verify_issuer,
            token_use=self.token_use, leeway=self.leeway, issuer=self.issuer, timeout=self.timeout,
        )

    def clear_cache(self) -> None:
        """Forget the downloaded keys."""
        self._cache.clear()

    def __repr__(self) -> str:
        return f'{type(self).__name__}({self.region!r}, {self.userpool_id!r}, jwks_url={self.jwks_url!r})'


__all__ = ['CognitoJWTVerifier']
