import sys

from setuptools import setup
from setuptools import find_packages


version = '0.1.0'

install_requires = [
    'acme>=0.21.1',
    'certbot>=0.21.1',
    'setuptools',
    'zope.interface',
]

setup(
    name='certbot-dns-euserv',
    version=version,
    description="EUserv DNS Authenticator plugin for Certbot",
    url='https://github.com/kraiz/certbot-dns-euserv',
    author='Lars Kreisz',
    author_email='lars.kreisz@gmail.com',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Plugins',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Security',
        'Topic :: System :: Installation/Setup',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
    ],
    packages=find_packages(),
    include_package_data=True,
    install_requires=install_requires,
    entry_points={
        'certbot.plugins': [
            'dns-euserv = certbot_dns_euserv.dns_euserv:Authenticator',
        ],
    }
)