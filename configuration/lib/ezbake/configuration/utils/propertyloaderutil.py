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

"""
propertyloaderutil module
"""
import glob
import os
import jprops



def stringPropertyNames(prop):
    """Returns a list of string property names in the property dict"""
    if not isinstance(prop, dict):
        raise TypeError('Expecting a dict type. Got %s' % type(prop).__name__)
    return [x for x in prop if isinstance(x, str)]


def isEmpty(prop):
    """Returns False if the property dict is not empty. True otherwise"""
    return prop is None or not stringPropertyNames(prop)


def checkForCollisions(toCheckAgainst, toCheck):
    """Checks for keys that are present in both dicts"""
    if not isinstance(toCheckAgainst, dict) or not isinstance(toCheck, dict):
        raise TypeError('toCheckAgainst and toCheck must be dicts')
    for key in stringPropertyNames(toCheck):
        if key in toCheckAgainst:
            raise RuntimeWarning('%s has already been defined' % key)


def mergeProperties(mergeWith, toMerge, shouldOverride=True):
    """Merges two property dicts"""
    if not shouldOverride:
        checkForCollisions(mergeWith, toMerge)
    mergeWith.update(toMerge)


def loadPropertiesFromFileHandle(fh):
    """Returns a property dict loaded from a open file handle"""
    return jprops.load_properties(fh)


def loadPropertiesFromFile(filename):
    """Returns a property dict loaded from a file"""
    if not isinstance(filename, str):
        raise TypeError('File name specified is not a string')
    if not filename:
        raise ValueError('filename specified cannot be empty')

    try:
        with open(filename) as fp:
            return loadPropertiesFromFileHandle(fp)
    except IOError as ex:
        raise IOError('Could not load properties file - %s' % ex)


def loadPropertiesFromDirectory(dirpath, shouldOverride=True):
    """
    Returns a property dict loaded from the specified directory.
    The directory is searched for files ending with '*.properties'
    """
    props = {}

    for propFile in glob.glob(os.path.join(dirpath, '*.properties')):
        prop = loadPropertiesFromFile(propFile)
        if not shouldOverride:
            checkForCollisions(props, prop)
        props.update(prop)

    return props

