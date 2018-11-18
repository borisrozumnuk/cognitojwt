from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='cognitojwt',
    version='0.4.3',
    description='Decode and verify Amazon Cognito JWT tokens',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='http://github.com/borisrozumnuk/cognitojwt',
    author='Boris Rozumniuk',
    author_email='borisrozumnuk@gmail.com',
    license='MIT',
    platforms='Any',
    install_requires=['python-jose', 'requests', 'aiohttp', 'async_lru'],
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
    zip_safe=False)
