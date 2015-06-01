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

from pkg_resources import resource_filename
import nose.tools as nt
import os

from ezbake.configuration.constants import constants
from ezbake.configuration.EzConfiguration import EzConfiguration
from ezbake.configuration.loaders.DirectoryConfigurationLoader import DirectoryConfigurationLoader
from ezbake.configuration.helpers import SystemConfiguration
from ezbake.configuration.security.CryptoImplementations import SharedSecretTextCryptoImplementation, NoOpTextCryptoImplementation

#Globals
CONFIG = None
EZBAKE_SECRET_ENV_VARIABLE = "EZBAKE_SECRET"

def setupTests():
    loader = DirectoryConfigurationLoader(resource_filename('tests', 'config'))
    ez_props = EzConfiguration(loader).getProperties()
    ez_props[constants.EZBAKE_SHARED_SECRET_ENVIRONMENT_VARIABLE] = EZBAKE_SECRET_ENV_VARIABLE
    global CONFIG
    CONFIG = SystemConfiguration(ez_props)


@nt.with_setup(setup=setupTests)
def testGetLogFilePathForService():
    logPath = CONFIG.getLogFilePath(None, 'testservice')
    nt.ok_(logPath.endswith(os.sep + os.path.join('testservice', 'testservice' + '.log')))


@nt.with_setup(setup=setupTests)
def testGetCryptoImplementer():
    os.environ[EZBAKE_SECRET_ENV_VARIABLE] = "p@ssw0rd"
    nt.ok_(isinstance(CONFIG.getTextCryptoImplementer(), SharedSecretTextCryptoImplementation))

    #remove the shared secret from the ezproperties object and check the default crypto implementation
    del os.environ[EZBAKE_SECRET_ENV_VARIABLE]
    nt.ok_(isinstance(CONFIG.getTextCryptoImplementer(), NoOpTextCryptoImplementation))

