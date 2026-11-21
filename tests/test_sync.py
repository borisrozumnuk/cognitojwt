import threading

from cognitojwt import jwt_sync

from .conftest import REGION, USERPOOL_ID


def _run_in_threads(target, count=20):
    results, errors = [], []
    barrier = threading.Barrier(count)

    def worker():
        barrier.wait()
        try:
            results.append(target())
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    return results


def test_concurrent_threads_share_one_download(jwks_server, make_token):
    jwks_server.delay = 0.2
    token = make_token()
    results = _run_in_threads(lambda: jwt_sync.decode(token, REGION, USERPOOL_ID))
    assert all(r['sub'] == 'user-sub' for r in results)
    assert jwks_server.requests == 1


def test_concurrent_force_refresh_shares_one_download(jwks_server):
    url = jwks_server.base_url + '/jwks.json'
    jwt_sync.get_keys(url)
    jwks_server.delay = 0.2
    _run_in_threads(lambda: jwt_sync.get_keys(url, force_refresh=True))
    assert jwks_server.requests == 2
    # A later explicit refresh still downloads.
    jwks_server.delay = 0
    jwt_sync.get_keys(url, force_refresh=True)
    assert jwks_server.requests == 3
