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

from .loaders.OpenShiftConfigurationLoader import OpenShiftConfigurationLoader
from .loaders.DirectoryConfigurationLoader import DirectoryConfigurationLoader
from .properties import EzProperties
from .utils import propertyloaderutil

class EzConfiguration(object):
    '''
    EzConfiguraiton Class
    Handles loading the 'configuration'. It does this by calling the resource loaders passed to it via *args
    '''

    def __init__(self, *args):
        self.__configuration = {}
        args = args if args else [DirectoryConfigurationLoader(), OpenShiftConfigurationLoader()]
        for arg in args:
            if arg.isLoadable():
                configuration = arg.loadConfiguration()
                if configuration is not None and len(configuration) > 0:
                    propertyloaderutil.mergeProperties(self.__configuration, configuration)

    def getProperties(self, crytoImplementer=None):
        ezprops = EzProperties(self.__configuration)
        if crytoImplementer is not None:
            ezprops.setTextCryptoImplementer(crytoImplementer)
        return ezprops
