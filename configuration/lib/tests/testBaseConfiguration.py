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
from ezbake.configuration.helpers import BaseConfiguration
from ezbake.configuration.loaders.DirectoryConfigurationLoader import DirectoryConfigurationLoader



def testBaseConfiguration():
    ezConfig = EzConfiguration(DirectoryConfigurationLoader(resource_filename('tests', 'config')))
    config = BaseConfiguration(ezConfig.getProperties())
    #private member access used for testing
    nt.eq_('testapp', config._ezprops.get('application.name'))

def testWithNamespacePrefixing():
    ezConfig = EzConfiguration(DirectoryConfigurationLoader(resource_filename('tests', 'config')))
    config = BaseConfiguration(ezConfig.getProperties(), namespace='TestNamespace')
    #private member access used for testing
    nt.eq_('TestUserWithNamespace', config._ezprops.get(config._parseKey('accumulo.username')))
