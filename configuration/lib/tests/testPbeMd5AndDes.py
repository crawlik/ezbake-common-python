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
from ezbake.configuration.security import PbeMd5AndDes


def testEncryption():
	def runEncryptionTest(plaintext, password, javaEncryptedString):
		salt = 'EncryptionFTW'
		iterations = 1000
		encryptedText = PbeMd5AndDes.encrypt(plaintext, password, salt, iterations)
		nt.eq_(encryptedText, javaEncryptedString)
		decryptedText = PbeMd5AndDes.decrypt(encryptedText, password, salt, iterations)
		nt.eq_(plaintext, decryptedText)

	runEncryptionTest("TheKingOfTheNorth", "AWonderfulPassword", "u+rBvJ4eClCtfuLKSopC1yq7QAfjShdG")
	runEncryptionTest("agreatstring", "alsoagreatpassword", "oU+otnnF+D/z0IJbF1/fGw==")
	runEncryptionTest("!@#$%^&()211938fjd3948d!", "@h@rd3rp@55w0rd", "3xci9oIzGPKXJ4xe1Ct4ePxl9Hho5TvFOFjAefTEjys=")

