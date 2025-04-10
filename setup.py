#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="grecon",
    version="1.0.0",
    author="Mohamed Gebril",
    author_email="your.email@example.com",
    description="Advanced Network Reconnaissance Tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Moh-Gebril/grecon",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Environment :: Console",
    ],
    python_requires=">=3.6",
    install_requires=[
        "argparse",
    ],
    entry_points={
        "console_scripts": [
            "grecon=grecon.cli:main",
        ],
    },
)
