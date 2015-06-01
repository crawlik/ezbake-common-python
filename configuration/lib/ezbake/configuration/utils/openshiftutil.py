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

import os


def getRepoDir():
    repoDir = os.getenv('OPENSHIFT_REPO_DIR')
    if repoDir is None:
        raise LookupError('Unable to lookup environ variable OPENSHIFT_REPO_DIR')
    return repoDir


def getConfigurationDir():
    return os.path.join(getRepoDir(), 'config')


def inOpenShiftContainer():
    return os.getenv("OPENSHIFT_REPO_DIR") is not None


def getThriftPrivateInfo():
    ip = os.getenv('OPENSHIFT_JAVA_THRIFTRUNNER_IP')
    if ip is None:
        raise LookupError('Error in looking up environ variable OPENSHIFT_JAVA_THRIFTRUNNER_IP')
    port = os.getenv('OPENSHIFT_JAVA_THRIFTRUNNER_TCP_PORT')
    if port is None:
        raise LookupError('Error in looking up environ variable OPENSHIFT_JAVA_THRIFTRUNNER_TCP_PORT')
    return ip, port
