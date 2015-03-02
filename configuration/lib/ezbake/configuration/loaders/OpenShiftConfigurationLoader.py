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

from .DirectoryConfigurationLoader import DirectoryConfigurationLoader
from ..utils import openshiftutil


class OpenShiftConfigurationLoader(DirectoryConfigurationLoader):
    '''Class will attempt to load properties from a OpenShift Gears configuration directory.
       Which is a directory inside of OpenShift's git repository.  
       That directory can be found on the OpenShift gear by look at OPENSHIFT_REPO_DIR environment 
       variable from inside of the gear.  The configuration directory is the "config" directory 
       under the OPENSHIFT_REPO_DIR.
    '''

    def __init__(self):
        super(OpenShiftConfigurationLoader, self).__init__()

    def getDirectory(self):
        if openshiftutil.inOpenShiftContainer():
            return openshiftutil.getConfigurationDir()

