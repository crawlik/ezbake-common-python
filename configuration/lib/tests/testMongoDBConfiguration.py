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

from ezbake.configuration.EzConfiguration import EzConfiguration
from ezbake.configuration.helpers import MongoDBConfiguration
from ezbake.configuration.loaders.DirectoryConfigurationLoader import DirectoryConfigurationLoader



## Globals
CONFIG = None

def setupTests():
    loader = DirectoryConfigurationLoader(resource_filename('tests', 'config'))
    ezconfig = EzConfiguration(loader)
    global CONFIG
    CONFIG = MongoDBConfiguration(ezconfig.getProperties())


@nt.with_setup(setup=setupTests)
def testHostName():
    nt.eq_('localhost', CONFIG.getMongoDBHostName())

@nt.with_setup(setup=setupTests)
def testDbName():
    nt.eq_('testdatabase', CONFIG.getMongoDBDatabaseName())

@nt.with_setup(setup=setupTests)
def testUserPassword():
    nt.eq_('m0ng0p@ssw0rd', CONFIG.getMongoDBPassword())

@nt.with_setup(setup=setupTests)
def testUserName():
    nt.eq_('mongo_user', CONFIG.getMongoDBUserName())

@nt.with_setup(setup=setupTests)
def testUseSSL():
    nt.eq_(True, CONFIG.useMongoDBSSL())
