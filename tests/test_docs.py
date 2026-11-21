"""Keep docs/ (GitHub Pages, llms.txt) in line with the package."""
import json
import re
import time
from pathlib import Path

import pytest
from joserfc import jwk, jwt

import cognitojwt

DOCS = Path(__file__).resolve().parent.parent / 'docs'
LLMS = (DOCS / 'llms.txt').read_text(encoding='utf-8')
LLMS_FULL = (DOCS / 'llms-full.txt').read_text(encoding='utf-8')
INDEX = (DOCS / 'index.html').read_text(encoding='utf-8')


def test_version_is_current():
    assert f'Version: {cognitojwt.__version__}' in LLMS_FULL
    assert f'Current version: {cognitojwt.__version__}.' in LLMS
    assert f'<li>v{cognitojwt.__version__}</li>' in INDEX


@pytest.mark.parametrize('name', cognitojwt.__all__)
def test_public_names_are_documented(name):
    assert f'`{name}`' in LLMS_FULL
    assert name in INDEX


def test_constants_table_matches():
    for name, value in re.findall(r'^\| `([A-Z_]+)` \| `([^`]+)` \|', LLMS_FULL, re.M):
        assert repr(getattr(cognitojwt.constants, name)) == value, name


def test_llms_txt_format():
    # https://llmstxt.org/: an H1, a blockquote summary, then H2 sections of links.
    lines = LLMS.splitlines()
    assert lines[0] == '# cognitojwt'
    assert lines[2].startswith('> ')
    assert '## Docs' in LLMS and '## Optional' in LLMS
    assert 'https://borisrozumnuk.github.io/cognitojwt/llms-full.txt' in LLMS


def test_local_key_example(tmp_path):
    # The "Tests with a local key" example of llms-full.txt.
    path = tmp_path / 'jwks.json'
    key = jwk.RSAKey.generate_key(2048, parameters={'kid': 'test', 'alg': 'RS256'})
    path.write_text(json.dumps({'keys': [key.as_dict(private=False)]}))
    verifier = cognitojwt.CognitoJWTVerifier('local', 'local_pool', jwks_url=str(path))
    token = jwt.encode(
        {'alg': 'RS256', 'kid': 'test'},
        {'sub': 'u', 'token_use': 'access', 'exp': int(time.time()) + 60},
        key,
    )
    assert verifier.verify(token)['sub'] == 'u'
