#!/usr/bin/env python
# Copyright 2017 Sergey Berezin

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup, find_packages

setup(
    name='acme-tiny-cron',
    version='0.1',
    description='Cron job script wrapper for acme-tiny',
    long_description='Cron job script wrapper for acme-tiny',
    classifiers=[
        'Programming Language :: Python',
    ],
    packages=find_packages(exclude=['*.test']),
    install_requires=[
        'acme-tiny',
        'cryptography',
        'protobuf',
    ],
    package_data={
        '': ['*.md'],
    },
    scripts=['scripts/acme_tiny_cron'],
)
