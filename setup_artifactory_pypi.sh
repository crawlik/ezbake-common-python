#!/bin/bash
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

ARTIFACTORY_PROTO=${ARTIFACTORY_PROTO:-"https"}

if [[ -z $ARTIFACTORY_BASE_URL || -z $ARTIFACTORY_USER || -z $ARTIFACTORY_PASS ]]; then

    echo "Cannot setup artifactory pypi without environment variables ARTIFACTORY_BASE_URL, ARTIFACTORY_USER, and ARTIFACTORY_PASS" >&2
    exit 1
fi

ARTIFACTORY_ENCRYPTED_PASSWORD=$(curl -su ${ARTIFACTORY_USER}:${ARTIFACTORY_PASS} "${ARTIFACTORY_PROTO}://${ARTIFACTORY_BASE_URL}/api/security/encryptedPassword")


# Back up existing configuration
if [[ -x ~/.pip/pip.conf ]]; then
    cp ~/.pip/pip.conf ~/.pip/pip.conf.bak
fi
if [[ -x ~/.pypirc ]]; then
    cp ~/.pypirc ~/.pypirc.bak
fi

# Write new config file
mkdir -p ~/.pip

cat <<EOF > ~/.pip/pip.conf
[global]
index-url=${ARTIFACTORY_PROTO}://${ARTIFACTORY_USER}:${ARTIFACTORY_ENCRYPTED_PASSWORD}@${ARTIFACTORY_BASE_URL}/api/pypi/pypi/simple
EOF

cat <<EOF > ~/.pypirc
[distutils]
index-servers = ezbake-local

[ezbake-local]
repository: ${ARTIFACTORY_PROTO}://${ARTIFACTORY_BASE_URL}/api/pypi/pypi-local
username: ${ARTIFACTORY_USER}
password: ${ARTIFACTORY_ENCRYPTED_PASSWORD}
EOF
