#!/usr/bin/env python
#   Copyright (C) 2013-2014 Computer Sciences Corporation
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""Setup script for installing ezDiscovery as a module."""

from setuptools import setup, find_packages

setup(
    name='ezbake-discovery',
    description='Python module for talking to ezDiscovery service.',
    version='2.1',
    license='Apache License 2.0',
    author='EzBake Developers',
    author_email='developers@ezbake.io',
    namespace_packages=['ezbake'],
    packages=find_packages('lib', exclude=["tests", "*.examples", "*.examples.*"]),
    package_dir={'': 'lib'},
    entry_points={
        'console_scripts': [
            'ezdiscovery = ezbake.discovery:main'
        ]
    },
    install_requires=[
        'kazoo>=2.0'
    ]
)
