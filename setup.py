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

from distutils.command.install import install
from setuptools import setup, find_packages
import subprocess

# When updating versions, also update pip2.deps and pip3.deps.
INSTALL_REQUIRES = [
    'acme-tiny==4.0.4',
    'cryptography==2.2.2',
    'protobuf==3.5.2.post1',
]


def pip_install(package):
    p = subprocess.Popen(['pip', 'install', package], stdout=subprocess.PIPE)
    out, err = p.communicate()
    for line in out.splitlines():
        print(line.decode('utf-8'))


# For some reason, on Mac OS X `./setup.py install` wants to build
# cryptography package, while `pip install cryptography` just installs
# a prebuilt wheel. Here we force `pip install` for all the
# requirements before attempting to install through setup.py.
class Install(install):
  def run(self):
    for req in INSTALL_REQUIRES:
      pip_install(req)
    install.run(self)


setup(
    name='acme-tiny-cron',
    version='0.2',
    description='Cron job script wrapper for acme-tiny',
    long_description='Cron job script wrapper for acme-tiny',
    classifiers=[
        'Programming Language :: Python',
    ],
    cmdclass = {
      'install': Install,
    },
    packages=find_packages(exclude=['*.test']),
    install_requires=INSTALL_REQUIRES,
    package_data={
        '': ['*.md'],
    },
    scripts=['scripts/acme_tiny_cron'],
)
