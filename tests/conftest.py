import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from joserfc import jwk, jwt

from cognitojwt import constants, jwt_async, jwt_sync

REGION = 'eu-west-1'
USERPOOL_ID = 'eu-west-1_TestPool1'
APP_CLIENT_ID = 'test-app-client-id'
ISSUER = constants.ISSUER_TEMPLATE.format(REGION, USERPOOL_ID)
KID = 'test-kid-1'


def make_key(kid):
    return jwk.RSAKey.generate_key(2048, parameters={'kid': kid, 'alg': 'RS256', 'use': 'sig'})


@pytest.fixture(scope='session')
def private_key():
    return make_key(KID)


@pytest.fixture(scope='session')
def other_key():
    """A key that is *not* published in the JWKS."""
    return make_key('other-kid')


def jwks_for(*keys):
    return {'keys': [k.as_dict(private=False) for k in keys]}


@pytest.fixture
def make_token(private_key):
    def _make(token_use='id', key=None, headers=None, drop=(), **overrides):
        now = int(time.time())
        claims = {
            'sub': 'user-sub',
            'iss': ISSUER,
            'token_use': token_use,
            'iat': now,
            'exp': now + 3600,
        }
        claims['aud' if token_use == 'id' else 'client_id'] = APP_CLIENT_ID
        claims.update(overrides)
        for name in drop:
            claims.pop(name, None)
        signing_key = key or private_key
        header = {'alg': 'RS256', 'kid': signing_key.kid}
        header.update(headers or {})
        return jwt.encode(header, claims, signing_key)
    return _make


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.delenv(constants.JWKS_PATH_ENV, raising=False)
    jwt_sync.get_keys.cache_clear()
    jwt_async.get_keys_async.cache_clear()
    yield
    jwt_sync.get_keys.cache_clear()
    jwt_async.get_keys_async.cache_clear()


@pytest.fixture
def jwks_file(tmp_path, monkeypatch, private_key):
    path = tmp_path / 'jwks.json'
    path.write_text(json.dumps(jwks_for(private_key)))
    monkeypatch.setenv(constants.JWKS_PATH_ENV, str(path))
    return path


class JWKSServer:
    def __init__(self, jwks):
        self.jwks = jwks
        self.status = 200
        self.requests = 0
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                server.requests += 1
                body = json.dumps(server.jwks).encode()
                self.send_response(server.status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.base_url = f'http://127.0.0.1:{self.httpd.server_address[1]}'
        self.thread = threading.Thread(
            target=self.httpd.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True
        )
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def jwks_server(monkeypatch, private_key):
    """Serves the JWKS over HTTP and points the default Cognito URL template to it."""
    server = JWKSServer(jwks_for(private_key))
    monkeypatch.setattr(
        constants, 'PUBLIC_KEYS_URL_TEMPLATE', server.base_url + '/{}/{}/.well-known/jwks.json'
    )
    yield server
    server.close()
