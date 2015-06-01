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

import nose.tools as nt

from ezbake.configuration.security.CryptoImplementations import SharedSecretTextCryptoImplementation
from ezbake.configuration.security.CryptoImplementations import NoOpTextCryptoImplementation
from ezbake.configuration.properties import EzProperties
from ezbake.configuration.utils.propertyencryptionutil import isEncryptedValue


def testDetectingEncryptedValues():
    nt.eq_(True, isEncryptedValue('ENC~(value)~'))
    nt.eq_(False, isEncryptedValue('testValue'))
    nt.eq_(False, isEncryptedValue('ENC(value)'))

    props = EzProperties({'theKey': 'ENC~(theValue)~'})
    props.setTextCryptoImplementer(NoOpTextCryptoImplementation())
    nt.eq_('theValue', props.getProperty('theKey', None))


def testEncryptingAndDecryptingProperties():
    encryptionPassword = 'p@$$w0rd'
    props = EzProperties()

    #unencrypted
    props.setTextCryptoImplementer(SharedSecretTextCryptoImplementation(encryptionPassword))
    props['key_1'] = 'GaurdiansOfTheGalaxy'
    nt.eq_('GaurdiansOfTheGalaxy', props.getProperty('key_1', None))
    props.setTextCryptoImplementer(NoOpTextCryptoImplementation())
    nt.eq_('GaurdiansOfTheGalaxy', props.getProperty('key_1', None))

    #encrypted
    props.setTextCryptoImplementer(SharedSecretTextCryptoImplementation(encryptionPassword))
    props.setProperty('key_2', 'AmazingSpiderman', True)
    nt.eq_('AmazingSpiderman', props.getProperty('key_2', None))
    props.setTextCryptoImplementer(NoOpTextCryptoImplementation())
    nt.eq_('q/+M4peluGo4QdHKr40J0uS9MeI2fYrF', props.getProperty('key_2', None))
    props.setTextCryptoImplementer(SharedSecretTextCryptoImplementation(encryptionPassword))
    nt.eq_('AmazingSpiderman', props.getProperty('key_2', None))

