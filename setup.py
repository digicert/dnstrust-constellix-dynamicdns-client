"""
Constellix Dynamic DNS Client.

Requires Python 3.5 or later.

@see https://constellix.com/
@license MIT
"""

import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='constellix_dynamicdns_client',
    version='1.0.0',
    author='Constellix, a division of Tiggee LLC',
    author_email='sales@constellix.com',
    description='Dynamic DNS Client for Constellix DNS',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://constellix.com/',
    packages=setuptools.find_packages(),
    python_requires='>=3.5',
    install_requires=[
        'requests>=2.23.0'
    ],
    entry_points={
        'console_scripts': ['ddns-client=ddns_client:main'],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
