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
import os
import nose.tools as nt

from ezbake.configuration.constants import constants
from ezbake.configuration.EzConfiguration import EzConfiguration
from ezbake.configuration.helpers import SecurityConfiguration
from ezbake.configuration.loaders.DirectoryConfigurationLoader import DirectoryConfigurationLoader




#Globals
CONFIG = None
SSL_CONFIG = 'config/ssl'

def setupTests():
    loader = DirectoryConfigurationLoader(resource_filename('tests', 'config'))
    ezconfig = EzConfiguration(loader)
    global CONFIG
    CONFIG = SecurityConfiguration(ezconfig.getProperties())
    
def setupSslConfigDir():
    setupTests()
    global SSL_CONFIG
    SSL_CONFIG = resource_filename('tests', os.path.join('config', 'ssl'))
    global CONFIG
    CONFIG._ezprops[constants.EZBAKE_CERTIFICATES_DIRECTORY] = SSL_CONFIG
    CONFIG = SecurityConfiguration(CONFIG._ezprops)



@nt.with_setup(setup=setupTests)
def testUserCacheTTL():
    nt.eq_(43200, CONFIG.getUserCacheTTL())

@nt.with_setup(setup=setupTests)
def testUserCacheSize():
    nt.eq_(1000, CONFIG.getUserCacheSize())

@nt.with_setup(setup=setupTests)
def testRequestsExpiration():
    nt.eq_(60, CONFIG.getRequestsExpiration())

@nt.with_setup(setup=setupTests)
def testTokenExpiration():
    nt.eq_(7200, CONFIG.getTokenExpiration())

@nt.with_setup(setup=setupTests)
def testUseMockServer():
    nt.assert_false(CONFIG.useMockServer())

@nt.with_setup(setup=setupTests)
def testIsPeerAuthRequired():
    nt.eq_(False, CONFIG.isPeerAuthRequired())

@nt.with_setup(setup=setupSslConfigDir)
def testSslAccessors():
    nt.eq_(os.path.join(SSL_CONFIG, SecurityConfiguration.DEFAULT_PRIVATE_KEY), CONFIG.getPrivateKey())
    nt.eq_(os.path.join(SSL_CONFIG, SecurityConfiguration.DEFAULT_SERVICE_PUBLIC_KEY), CONFIG.getServicePublicKey())
    nt.eq_(os.path.join(SSL_CONFIG, SecurityConfiguration.DEFAULT_SSL_CERT), CONFIG.getSslCertificate())
    nt.eq_(os.path.join(SSL_CONFIG, SecurityConfiguration.DEFAULT_TURSTED_SSL_CERTS), CONFIG.getTrustedSslCerts())

    nt.eq_(os.path.join(SSL_CONFIG, 'test.priv'), CONFIG.getPrivateKey('testService'))
    nt.eq_(os.path.join(SSL_CONFIG, 'test.pub'), CONFIG.getServicePublicKey('testService'))

    CONFIG.setPrivateKey('testService')
    CONFIG.setPublicKey('testService')
    nt.ok_(CONFIG.hasPrivateKeySet())
    nt.ok_(CONFIG.hasPublicKeySet())
    nt.ok_(CONFIG.hasKeysSet())

    data = 'HelloWorld\nThis is:a {new} \"Day\"\n\n';
    nt.ok_(CONFIG.verify(data, CONFIG.sign(data)))

