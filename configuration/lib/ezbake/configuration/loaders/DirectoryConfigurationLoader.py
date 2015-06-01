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

'''
'''

import os
from ..utils import propertyloaderutil
from .EzConfigurationLoader import EzConfigurationLoader


class DirectoryConfigurationLoader(EzConfigurationLoader):
    '''This class will attempt to load properties from a directory.  
       It looks for this directory either by the user passing it into the constructor.
       If not the loader will first attempt to load from an environment variable EZCONFIGURATION_DIR, 
       and if that fails then it will use the default directory /etc/sysconfig/ezbake.
    '''

    DEFAULT_EZCONFIGURATION_DIR = '/etc/sysconfig/ezbake'
    EZCONFIGURATION_DIR_VAR = 'EZCONFIGURATION_DIR'


    def __init__(self, dir=None):
        super(DirectoryConfigurationLoader, self).__init__()
        self.directory = dir if dir is not None else self.getDirectory()
        self.configuration = {}

    def getDirectory(self):
        try:
            return next(x for x in [os.getenv(self.EZCONFIGURATION_DIR_VAR), self.DEFAULT_EZCONFIGURATION_DIR] if x is not None)
        except StopIteration:
            return None

    def loadConfiguration(self):
        if not self.isLoadable():
            raise RuntimeError('loader is not loadable')

        if os.path.isdir(self.directory):
            self.configuration = propertyloaderutil.loadPropertiesFromDirectory(self.directory, True)
            if self.configuration:
                return self.configuration
            else:
                pass #no need to raise error if directory loaded doesn't have any property files
                #raise IOError("Could not load properties from " + self.directory)

    def isLoadable(self):
        return False if self.directory == None or not os.path.isdir(self.directory) else True


