#!/bin/bash
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

# Script to setup base build environment.

cd `dirname $0`
SCRIPTS_PATH=`pwd`

cd ~

DEP_FOLDER=".ez_dev"

VERSION_VIRTUALENV="1.11.4"
ZOOKEEPER_VERSION="3.4.5"

APT=`which apt-get 2>/dev/null`

# Short of compiling our own Python version the base system must have the
# development header files available.
if [ -n "$APT" ]; then
    sudo apt-get update
    sudo apt-get -y upgrade
    sudo apt-get -y install python-dev
else
    sudo yum -y upgrade
    sudo yum -y install python-devel
fi

# Use the home folder of the current user to avoid permissions issues and not
# bog down the bootstrap process when using Vagrant by having larger file
# downloaded to the shared folder.
if [ ! -d "$DEP_FOLDER" ]; then
    mkdir $DEP_FOLDER
fi
cd $DEP_FOLDER

# Add virtualenv to system Python. No other system level Python changes should
# be made.
VIRUTALENV=`which virtualenv 2>/dev/null`
if [ -z "$VIRUTALENV" ]; then
    rm -rf virtualenv-$VERSION_VIRTUALENV virtualenv-$VERSION_VIRTUALENV.tar.gz
    wget --no-check-certificate \
        https://pypi.python.org/packages/source/v/virtualenv/virtualenv-$VERSION_VIRTUALENV.tar.gz
    tar -xzf virtualenv-$VERSION_VIRTUALENV.tar.gz
    cd virtualenv-$VERSION_VIRTUALENV
    sudo python setup.py install
    cd ..
fi

# Create the virtual environment.
# TODO(jmears): Make a command line flag to force virtual environment rebuild.
if [ ! -d py ]; then
    virtualenv py
fi
# Activate the virtualenv to make the rest of the commands easier to type.
source ~/$DEP_FOLDER/py/bin/activate

# Kazoo is a simple Python client for Zookeeper.
pip install kazoo

# pep8 is a style checker for python code.
pip install pep8

if [ -n "$APT" ]; then
    sudo apt-get -y install default-jre
else
    sudo yum -y install java-1.7.0-openjdk
fi

if [ ! -d "zookeeper" ]; then
    wget http://psg.mtu.edu/pub/apache/zookeeper/zookeeper-$ZOOKEEPER_VERSION/zookeeper-$ZOOKEEPER_VERSION.tar.gz
    tar -xzf zookeeper-$ZOOKEEPER_VERSION.tar.gz
    mv zookeeper-$ZOOKEEPER_VERSION zookeeper
    cd zookeeper/conf
    cp zoo_sample.cfg zoo.cfg
    cd ../..
fi
