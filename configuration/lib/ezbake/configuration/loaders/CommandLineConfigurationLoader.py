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

import cStringIO
import argparse
from ..utils import propertyloaderutil
from .EzConfigurationLoader import EzConfigurationLoader


class CommandLineConfigurationLoader(EzConfigurationLoader):
    """This class will attempt to load properties from the command line"""

    DEFAULT_CLI_OPTION_FLAG = '-D'

    def __init__(self, flag=DEFAULT_CLI_OPTION_FLAG):
        super(CommandLineConfigurationLoader, self).__init__()
        if not isinstance(flag, str):
            raise TypeError("'flag' is not a string")
        self.__flag = flag
        self.__args = None

    def _parse_cli(self):
        parser = argparse.ArgumentParser()
        parser.add_argument(self.__flag, nargs=1, action='append')

        try:
            self.__args, _ = parser.parse_known_args()
        except SystemExit as se:
            raise RuntimeError('Exception while parsing cli args: %s' % str(se))

    def _getlines(self):
        lines = getattr(self.__args, self.__flag.lstrip('-'))
        return [item for sublist in lines for item in sublist] if lines else None

    def loadConfiguration(self):
        if not self.isLoadable():
            raise RuntimeError('loader is not loadable')

        fh = cStringIO.StringIO()
        fh.write('\n'.join(self._getlines()))
        fh.seek(0)
        return propertyloaderutil.loadPropertiesFromFileHandle(fh)

    def isLoadable(self):
        self._parse_cli()
        return self._getlines() is not None
