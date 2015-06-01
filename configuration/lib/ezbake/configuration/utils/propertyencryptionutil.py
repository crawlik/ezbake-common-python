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

from ..security.CryptoImplementations import TextCrytoImplementation


class PropertyEncryptionUtilException(RuntimeError):
    '''Exception class for PropertyEncryptionUtil'''
    def __init__(self, *args):
        super(PropertyEncryptionUtilException, self).__init__(*args)



__PROPERTY_ENCRYPTION_PREFIX__ = "ENC~("
__PROPERTY_ENCRYPTION_SUFFIX__ = ")~"


def getInnerValue(value):
    try:
        return value[len(__PROPERTY_ENCRYPTION_PREFIX__):-len(__PROPERTY_ENCRYPTION_SUFFIX__)]
    except Exception as ex:
        raise  PropertyEncryptionUtilException(ex)


def isEncryptedValue(value):
    if not value:
        return False
    if not isinstance(value, str):
        return False
    trimmedValue = value.strip()
    return trimmedValue.startswith(__PROPERTY_ENCRYPTION_PREFIX__) and trimmedValue.endswith(__PROPERTY_ENCRYPTION_SUFFIX__)


def isEncryptedProperty(props, key):
    if not isinstance(props, dict):
        raise PropertyEncryptionUtilException('props must be a dict object')
    value = props.get(key)
    return isEncryptedValue(value)


def decryptPropertyValue(value, cryptoImplementor):
    if not isinstance(cryptoImplementor, TextCrytoImplementation):
        raise PropertyEncryptionUtilException('cryptoImplementor must be of type TextCrytoImplementation')
    return cryptoImplementor.decrypt(getInnerValue(value))


def decryptProperty(props, key, cryptoImplementor):
    if not isinstance(cryptoImplementor, TextCrytoImplementation):
        raise PropertyEncryptionUtilException('cryptoImplementor must be of type TextCrytoImplementation')
    if isEncryptedProperty(props, key):
        return decryptPropertyValue(props.get(key), cryptoImplementor)

def encryptPropertyValue(value, cryptoImplementor):
    if not isinstance(cryptoImplementor, TextCrytoImplementation):
        raise PropertyEncryptionUtilException('cryptoImplementor must be of type TextCrytoImplementation')
    return __PROPERTY_ENCRYPTION_PREFIX__ + cryptoImplementor.encrypt(value) + __PROPERTY_ENCRYPTION_SUFFIX__

