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

from Crypto.Hash import MD5
from Crypto.Cipher import DES

def encrypt(plaintext, password, salt='do provide default', iterations=1000):
    padding = 8 - len(plaintext) % 8
    plaintext += chr(padding) * padding
    result = key(password, salt, iterations)
    encoder = DES.new(result[:8], DES.MODE_CBC, result[8:16])
    encrypted = encoder.encrypt(plaintext)
    return encrypted.encode('base64').strip()

def decrypt(encryptedtext, password, salt='do provide default', iterations=1000):
    encryptedtext = encryptedtext.decode('base64')
    result = key(password, salt, iterations)
    encoder = DES.new(result[:8], DES.MODE_CBC, result[8:16])
    encrypted = encoder.decrypt(encryptedtext)
    pad = ord(encrypted[-1])
    encrypted = encrypted[:-pad]
    return encrypted

def key(password, salt, iterations):
    hasher = MD5.new()
    hasher.update(password)
    hasher.update(salt[:8])
    result = hasher.digest()
    for _ in range(1, iterations):
        hasher = MD5.new()
        hasher.update(result)
        result = hasher.digest()
    return result
