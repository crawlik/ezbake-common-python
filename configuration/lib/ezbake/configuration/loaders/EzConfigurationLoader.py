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

class EzConfigurationLoader(object):
    '''Abstract class for all configuration loaders
    '''

    def __init__(self):
        pass

    def loadConfiguration(self):
        '''
        Loads the property object
        
        Returns:
            dict: a properties dict (Implementors should return a blank properties object if no properties are loaded)
        '''
        return {}

    def isLoadable(self):
        '''
        Checks to see if this loader is loadable
        
        Returns:
            bool: True if the loader is loadable. False otherwise
        '''
        return False
