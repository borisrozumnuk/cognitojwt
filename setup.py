from setuptools import setup

setup(name='cognitojwt',
      version='0.1',
      description='Decode and verify Amazon Cognito JWT tokens',
      url='http://github.com/borisrozumnuk/cognitojwt',
      author='Boris Rozumniuk',
      author_email='borisrozumnuk@gmail.com',
      license='MIT',
      platforms='Any',
      install_requires=['python-jose', 'requests'],
      keywords='Amazin Cognito JWT',
      packages=['cognitojwt'],
      classifiers=[
        'Programming Language :: Python :: 3.6'
      ],
      zip_safe=False)
