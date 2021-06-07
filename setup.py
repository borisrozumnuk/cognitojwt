from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()


install_requires = [
    'python-jose[cryptography]'
]

sync_require = [
    'requests'
]

async_require = [
    'aiofile',
    'aiohttp',
    'async_lru'
]

test_require = {
    'requests',
    'aiohttp',
    'async_lru',
    'pytest==5.4.0',
    'pytest-asyncio==0.12.0',
    'attrs==19.1.0'
}


setup(
    name='cognitojwt',
    version='1.4.0',
    description='Decode and verify Amazon Cognito JWT tokens',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='http://github.com/borisrozumnuk/cognitojwt',
    author='Boris Rozumniuk',
    author_email='borisrozumnuk@gmail.com',
    license='MIT',
    platforms='Any',
    install_requires=install_requires,
    extras_require={
        'sync': sync_require,
        'async': async_require,
        'test': test_require
    },
    keywords='Amazon Cognito JWT',
    packages=['cognitojwt'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Operating System :: OS Independent',
    ],
    zip_safe=False
)
