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
from .EzConfigurationLoader import EzConfigurationLoader


class PropertiesConfigurationLoader(EzConfigurationLoader):
    '''Class providers an easy ezconfiguration loader that loads properties
    from an existing properties dict
    '''
    
    def __init__(self, props=None):
        super(PropertiesConfigurationLoader, self).__init__()
        self.properties = props

    def loadConfiguration(self):
        if not self.isLoadable():
            raise RuntimeError('loader is not loadable')
        return self.properties

    def isLoadable(self):
        return False if self.properties is None else self.properties != {}

