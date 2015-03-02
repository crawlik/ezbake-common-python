#   Copyright (C) 2013-2015 Computer Sciences Corporation
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

import nose.tools as nt
import sys
from ezbake.configuration.loaders.CommandLineConfigurationLoader import CommandLineConfigurationLoader


def testUnLoadable():
    loader = CommandLineConfigurationLoader()
    nt.assert_false(loader.isLoadable(), msg='Expected a non-loadable CLI loader')


def testLoadFromCli():
    # add cli properties to current execution
    sys.argv.append('-D ezbake.test.cli=true')
    sys.argv.append('-D test.class=ezbake.class.NoNamedClass')
    sys.argv.append('-D test.hosts=localhost:1234,localhost:4567')

    loader = CommandLineConfigurationLoader()
    props = loader.loadConfiguration()

    nt.eq_('true', props.get('ezbake.test.cli'))
    nt.eq_('ezbake.class.NoNamedClass', props.get('test.class'))
    nt.eq_('localhost:1234,localhost:4567', props.get('test.hosts'))


def testCustomFlags():

    # add cli properties to current execution
    sys.argv.append("--foo=defaultname=abc")
    sys.argv.append("-X defaultname=def")

    loader = CommandLineConfigurationLoader('--foo')
    nt.eq_(True, loader.isLoadable())
    nt.eq_('abc', loader.loadConfiguration().get('defaultname'))

    loader = CommandLineConfigurationLoader('-X')
    nt.eq_(True, loader.isLoadable())
    nt.eq_('def', loader.loadConfiguration().get('defaultname'))
