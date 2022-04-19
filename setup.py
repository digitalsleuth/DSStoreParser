#!/usr/bin/env python3
from setuptools import setup, find_packages

with open("README.md", encoding='utf8') as readme:
    long_description = readme.read()

setup(
    name="DSStoreParser",
    version="1.1.0",
    author="Nicole Ibrahim, Alastair Houghton, Corey Forman",
    license="Apache 2.0",
    url="https://github.com/digitalsleuth/DSStoreParser",
    description=("macOS .DS_Store Parser"),
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    include_package_data = True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License 2.0 (Apache-2.0)",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        "biplist",
        "mac_alias"
    ],
    entry_points={
        'console_scripts': [
            'dsstoreparser = ds_store_parser.DSStoreParser:main'
        ]
    },
    package_data={'': ['README.md, LICENSE']}
)
