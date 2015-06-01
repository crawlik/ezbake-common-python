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
from threading import RLock
from .security.CryptoImplementations import TextCrytoImplementation
from .utils.propertyencryptionutil import isEncryptedValue, decryptPropertyValue, encryptPropertyValue
from .utils import openshiftutil


class DuplicatePropertyException(RuntimeError):
    '''
    Exception class for duplicate properties collisions 
    '''
    def __init__(self, collisions):
        super(DuplicatePropertyException, self).__init__(str(collisions))



class EzProperties(dict):
    '''
    This class extends dict to add convenience methods to get primitives from strings, 
    deal with encrypted values. If you are going to be dealing with encrypted properties 
    then you are going to have to make sure to the set the TextCryptoProvider eg:

        EzProperties ezProperties = new EzProperties();
        ezProperties.setTextCryptoImplementer(new SharedSecretTextCryptoImplementation(os.getenv("SHARED_SECRET")));
    '''

    def __init__(self, *args):
        super(EzProperties, self).__init__(*args)
        self._cryptoImplementer = None
        self.__lock = RLock()

    def setTextCryptoImplementer(self, implementer):
        '''
        Set the crypto implementation to use when encrypting and decrypting values
        
        Args:
            implementer (TextCrytoImplementation): a text crypto implementation to use
        '''
        if not isinstance(implementer, TextCrytoImplementation):
            raise TypeError('implementer must be of type TextCrytoImplementation')
        with self.__lock:
            self._cryptoImplementer = implementer
        
    def getTextCryptoImplementer(self):
        '''
        Get the crypto implementer that this object is using to encrypt and decrypt values
        
        Returns:
            TextCrytoImplementation: a text crypto implementation
        '''
        return self._cryptoImplementer

    def getProperty(self, key, defaultValue=None):
        '''
        Obtains the property value for the specified key decrypting it if needed.
        
        Args:
            key (str): the property key
            defaultValue (str, optional): the default value to return if property doesn't exist
        '''
        return self.get(key, defaultValue)
    
    def setProperty(self, key, value, isEncrypted=False):
        '''
        Set a property value
        
        Args:
            key (str): the key to be placed in this properties object
            value (str): the value corresponding to the key
            isEncrypted (bool, optional): whether or not we should encrypt the property. Defaults to False
        '''
        self[key] = encryptPropertyValue(value, self._cryptoImplementer) if isEncrypted else value
        
    def getBoolean(self, propertyName, defaultValue):
        '''
        Get a property as a bool, if the property doesn't exist or can't be converted then we return the default value
        
        Args:
            propertyName (str): name of the property we are looking for (the key)
            defaultValue (bool): value to return if the key doesn't exist or the value can't be converted to a bool
            
        Returns:
            (bool): either the properly parsed bool or the default value if the key doesn't exist or can't be converted
        '''
        value = self.getProperty(propertyName, defaultValue)
        if isinstance(value, bool):
            return value
        if isinstance(value, basestring):
            value = value.strip().lower()
            if value == 'true' or value == 't' or value == '1':
                return True
            elif value == 'false' or value == 'f' or value == '0':
                return False
        return defaultValue

    def getDouble(self, propertyName, defaultValue):
        '''
        Get a property as a float, if the property doesn't exist or can't be converted then we return the default value
        Method returns a python float which is a C double
        
        Args:
            propertyName (str): name of the property we are looking for (the key)
            defaultValue (float): value to return if the key doesn't exist or the value can't be converted to a float
            
        Returns:
            (float): either the properly parsed float or the default value if the key doesn't exist or can't be converted
        '''
        return self.getFloat(propertyName, defaultValue)

    def getFloat(self, propertyName, defaultValue):
        '''
        Get a property as a float, if the property doesn't exist or can't be converted then we return the default value
        
        Args:
            propertyName (str): name of the property we are looking for (the key)
            defaultValue (float): value to return if the key doesn't exist or the value can't be converted to a float
            
        Returns:
            (float): either the properly parsed float or the default value if the key doesn't exist or can't be converted
        '''
        try:
            return float(self.getProperty(propertyName, defaultValue))
        except ValueError:
            return defaultValue

    def getInteger(self, propertyName, defaultValue):
        '''
        Get a property as an int, if the property doesn't exist or can't be converted then we return the default value
        
        Args:
            propertyName (str): name of the property we are looking for (the key)
            defaultValue (int): value to return if the key doesn't exist or the value can't be converted to an int
            
        Returns:
            (int): either the properly parsed int or the default value if the key doesn't exist or can't be converted
        '''
        try:
            return int(self.getProperty(propertyName, defaultValue))
        except ValueError:
            return defaultValue

    def getLong(self, propertyName, defaultValue):
        '''
        Get a property as a long, if the property doesn't exist or can't be converted then we return the default value
        
        Args:
            propertyName (str): name of the property we are looking for (the key)
            defaultValue (long): value to return if the key doesn't exist or the value can't be converted to a long
            
        Returns:
            (long): either the properly parsed long or the default value if the key doesn't exist or can't be converted
        '''
        try:
            return long(self.getProperty(propertyName, defaultValue))
        except ValueError:
            return defaultValue

    def getCollisions(self, toCheck):
        '''
        Check to see what properties would "collide" (have the same key name)
        
        Args:
            toCheck (EzProperty): the properties that we want to compare our properties with
            
        Returns:
            set: a set of string which are they keys that overlap
        '''
        if not isinstance(toCheck, dict):
            raise TypeError('toCheck must be of type dict')
        return self.viewkeys() & toCheck.viewkeys()

    def getPath(self, propertyName, defaultValue):
        '''
        Get file system path to represented by the property name
        If we're in an openshift container, prepend the openshift repo directory
        '''
        path = self.getProperty(propertyName, defaultValue)
        if path is None:
            return defaultValue
        if not openshiftutil.inOpenShiftContainer() or os.path.isabs(path):
            return path
        return os.path.join(openshiftutil.getRepoDir(), path)


    def mergeProperties(self, toMerge, shouldOverride=True):
        '''
        Merge one set of properties with our properties.
        
        Args:
            toMerge (EzProperties): properties that we want to merge into our own
            shouldOverride (bool, optional): whether or not we should just override. Default is True
        '''
        if not isinstance(toMerge, dict):
            raise TypeError('toMerge must be of type dict')
        if not shouldOverride:
            collisions = self.getCollisions(toMerge)
            if len(collisions) > 0:
                raise DuplicatePropertyException(collisions)
        self.update(toMerge)

    def __decrypt(self, value):
        if not isEncryptedValue(value):
            return value
        return decryptPropertyValue(value, self._cryptoImplementer)

    def __getitem__(self, *args):
        return self.__decrypt(super(EzProperties, self).__getitem__(*args))

    def get(self, *args):
        return self.__decrypt(super(EzProperties, self).get(*args))

    def pop(self, *args):
        raise NotImplementedError('EzPropreties does not support the pop api')

    def popitem(self):
        raise NotImplementedError('EzPropreties does not support the popitem api')

