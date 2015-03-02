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

from ezbake.configuration.constants.constants import ACCUMULO_PASSWORD
from ezbake.configuration.EzConfiguration import EzConfiguration
from ezbake.configuration.helpers import AccumuloConfiguration
from ezbake.configuration.loaders.DirectoryConfigurationLoader import DirectoryConfigurationLoader
from ezbake.configuration.security.CryptoImplementations import (SharedSecretTextCryptoImplementation,
                                                                 NoOpTextCryptoImplementation)



## Globals
CONFIG = None

def setupTests():
    loader = DirectoryConfigurationLoader(resource_filename('tests', 'config'))
    ezconfig = EzConfiguration(loader)
    cryptoPassword = 'password'
    cryptoImplementor = SharedSecretTextCryptoImplementation(cryptoPassword)
    ezprops = ezconfig.getProperties(cryptoImplementor)
    global CONFIG
    CONFIG = AccumuloConfiguration(ezprops)


@nt.with_setup(setup=setupTests)
def testGetAccumuloInstance():
    nt.eq_('accumulo_instance', CONFIG.getAccumuloInstance())


@nt.with_setup(setup=setupTests)
def testGetZooKeepers():
    nt.eq_('zoo1:2181,zoo2:2181', CONFIG.getZookeepers())


@nt.with_setup(setup=setupTests)
def testUseMock():
    nt.eq_(False, CONFIG.useMock())


@nt.with_setup(setup=setupTests)
def testGetUsername():
    nt.eq_('test', CONFIG.getUsername())


@nt.with_setup(setup=setupTests)
def testGetPassword():
    nt.eq_('foo', CONFIG.getPassword())


@nt.with_setup(setup=setupTests)
def testGetUsernameWithNamespace():
    config = AccumuloConfiguration(CONFIG._ezprops, 'TestNamespace')
    nt.eq_('TestUserWithNamespace', config.getUsername())

@nt.with_setup(setup=setupTests)
def testGetProxyParams():
    nt.eq_(42424, CONFIG.getProxyPort())
    nt.eq_('localhost', CONFIG.getProxyHost())


def testEncryptedProperties():
    ezconfig = EzConfiguration().getProperties()
    ezconfig[ACCUMULO_PASSWORD] = 'ENC~(value)~'
    nt.assert_equal('value', AccumuloConfiguration(ezconfig).getPassword())
