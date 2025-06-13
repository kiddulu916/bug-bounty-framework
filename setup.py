"""
Setup script for the Bug Bounty Framework (BBF).

This script allows the package to be installed with pip.
"""

import os
import re
from setuptools import setup, find_packages

# Read the README file for the long description
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

# Get package version
with open(os.path.join('bbf', '__init__.py'), 'r', encoding='utf-8') as f:
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", f.read(), re.M)
    if version_match:
        version = version_match.group(1)
    else:
        raise RuntimeError("Unable to find version string.")

# Read requirements from requirements.txt
with open('requirements.txt', 'r', encoding='utf-8') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name='bug-bounty-framework',
    version=version,
    description='A modular, extensible framework for bug bounty and security testing',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Kiddulu',
    author_email='916kiddulu@gmail.com',
    url='https://github.com/kiddulu916/bug-bounty-framework',
    packages=find_packages(include=['bbf', 'bbf.*']),
    package_data={
        'bbf': ['templates/*.j2'],
    },
    python_requires='>=3.8',
    install_requires=requirements,
    extras_require={
        'dev': [
            'pytest>=6.0',
            'pytest-cov>=2.0',
            'pytest-asyncio>=0.15.0',
            'black>=21.0',
            'isort>=5.0',
            'mypy>=0.900',
            'flake8>=3.9',
        ],
        'pdf': [
            'reportlab>=3.6.0',
            'WeasyPrint>=53.0',
        ],
        'jira': [
            'jira>=3.0.0',
        ],
        'defectdojo': [
            'defectdojo-api>=1.0.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'bbf=bbf.__main__:main',
        ],
        'bbf.plugins': [
            # Example plugins
            'subdomain_enumeration = bbf.plugins.recon.subdomain_enum:SubdomainEnumPlugin',
            'port_scanning = bbf.plugins.recon.port_scan:PortScannerPlugin',
        ],
    },
    classifiers=[
        'Development Status :: 3 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Security',
        'Intended Audience :: Bug Hunters',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: Software Development :: Testing',
        'Topic :: System :: Systems Administration',
    ],
    keywords='bug bounty security testing framework',
    project_urls={
        'Bug Reports': 'https://github.com/kiddulu916/bug-bounty-framework/issues',
        'Source': 'https://github.com/kiddulu916/bug-bounty-framework',
    },
)
