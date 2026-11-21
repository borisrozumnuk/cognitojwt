import os
import re

from setuptools import setup

HERE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(HERE, 'README.md'), encoding='utf-8') as fh:
    long_description = fh.read()

with open(os.path.join(HERE, 'cognitojwt', '__init__.py'), encoding='utf-8') as fh:
    version = re.search(r"^__version__ = '([^']+)'", fh.read(), re.M).group(1)


install_requires = [
    'joserfc>=0.9.0',
]

sync_require = [
    'requests>=2.32.4',
]

async_require = [
    'aiohttp>=3.9.4',
]

test_require = sync_require + async_require + [
    'pytest>=7',
    'pytest-asyncio>=0.21',
    'coverage[toml]>=6.5',
]


setup(
    name='cognitojwt',
    version=version,
    description='Decode and verify Amazon Cognito JWT tokens',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/borisrozumnuk/cognitojwt',
    project_urls={
        'Documentation': 'https://borisrozumnuk.github.io/cognitojwt/',
        'Changelog': 'https://github.com/borisrozumnuk/cognitojwt/blob/master/CHANGELOG.md',
        'Issues': 'https://github.com/borisrozumnuk/cognitojwt/issues',
    },
    author='Boris Rozumniuk',
    author_email='borisrozumnuk@gmail.com',
    license='MIT',
    platforms='Any',
    python_requires='>=3.8',
    install_requires=install_requires,
    extras_require={
        'sync': sync_require,
        'async': async_require,
        'test': test_require,
    },
    keywords='Amazon Cognito JWT',
    packages=['cognitojwt'],
    package_data={'cognitojwt': ['py.typed']},
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Programming Language :: Python :: 3.13',
        'Programming Language :: Python :: 3.14',
        'Framework :: AsyncIO',
        'Operating System :: OS Independent',
        'Typing :: Typed',
    ],
    zip_safe=False
)
