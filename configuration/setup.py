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

from setuptools import setup, find_packages

setup(
    name='ezbake-configuration',
    version='2.1rc1.dev',
    description='Ezbake Configuration - for python',
    license='Apache License 2.0',
    author='EzBake Developers',
    author_email='developers@ezbake.io',
    namespace_packages=['ezbake', 'ezbake.configuration'],
    packages=find_packages( 'lib', exclude=["tests", "*.examples", "*.examples.*"]),
    package_dir={'': 'lib'},
    install_requires=[
	'jprops>=1.0',
	'pycrypto>=2.6.1',
	'ezbake-configuration-constants>=2.1rc1.dev'
	]
    )
