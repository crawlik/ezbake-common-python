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
from .exceptions import SecurityException


class TextCrytoImplementation(object):
    '''Common interface for doing text encryption
    '''
    def __init__(self):
        pass
    
    def encrypt(self, message):
        raise NotImplementedError('Unimplemented method for generic TextCryptoImplementation')

    def decrypt(self, encryptedmessage):
        raise NotImplementedError('Unimplemented method for generic TextCryptoImplementation')



class NoOpTextCryptoImplementation(TextCrytoImplementation):
    '''Simple pass-through text crypto implementation that will not encrypt or decrypt anything.
    '''
    def __init__(self):
        super(NoOpTextCryptoImplementation, self).__init__()

    def encrypt(self, message):
        return message

    def decrypt(self, encryptedmessage):
        return encryptedmessage



class SharedSecretTextCryptoImplementation(TextCrytoImplementation):
    '''Shared secret text crypto implementation using a PbeMd5AndDes encryption algorithm 
    '''
    try:
        from . import PbeMd5AndDes as encryptor
    except ImportError as ex:
        raise SecurityException(ex)

    __SALT = "bouncycastle"
    __ITERATIONS = 1000


    def __init__(self, secret):
        super(SharedSecretTextCryptoImplementation, self).__init__()
        self.__password = secret

    def encrypt(self, message):
        try:
            return self.encryptor.encrypt(message, self.__password, self.__SALT, self.__ITERATIONS)
        except Exception as ex:
            raise SecurityException('Error in encrypting string: %s' % str(ex))

    def decrypt(self, encryptedmessage):
        try:
            return self.encryptor.decrypt(encryptedmessage, self.__password, self.__SALT, self.__ITERATIONS)
        except Exception as ex:
            raise SecurityException('Error in decrypting string: %s' % str(ex))

