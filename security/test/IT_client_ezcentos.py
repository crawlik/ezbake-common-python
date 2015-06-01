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
"""

import unittest
import nose.tools as nt
import base64
import OpenSSL.crypto as ossl

from ezbake.configuration.EzConfiguration import EzConfiguration
from ezbake.thrift.utils.clientpool import ThriftClientPool

from ezbake.base.thriftapi.ttypes import (ProxyUserToken, X509Info)

from ezbake.security.client import (EzSecurityClient, HTTP_HEADER_USER_INFO, HTTP_HEADER_SIGNATURE)
import ezbake.security.util as util
import jsonpickle

ZOO_CON_STR = '192.168.50.105:2181'

import logging
logging.basicConfig(level=logging.NOTSET, format='%(levelname)s: %(message)s')

class EzSecurityTest(unittest.TestCase):

    def setUp(self):
        self.appId = "client"
        ez_props = EzConfiguration().getProperties()
        ez_props["application.name"] = "client_name"
        ez_props["ezbake.security.app.id"] = self.appId
        ez_props["zookeeper.connection.string"] = ZOO_CON_STR
        ez_props["thrift.use.ssl"] = "false"
        ez_props["ezbake.security.ssl.dir"] = "test/certs/client/"

        self.global_client_pool = ThriftClientPool(ez_props)

        self.es_client = EzSecurityClient(ez_props, self.global_client_pool)

    def tearDown(self):
        self.global_client_pool.close()

    def IT_ping(self):
        nt.assert_true(self.es_client.ping())

    def IT_app_info(self):
        token = self.es_client.fetch_app_token(self.appId)

        nt.assert_is_not_none(token)
        nt.assert_equal(self.appId, token.tokenPrincipal.principal)
        nt.assert_equal(self.appId, token.validity.issuedFor)

    @staticmethod
    def _make_dn(subject):
        x509 = X509Info(subject=subject)
        token = ProxyUserToken(x509=x509,
                               issuedBy="EzSecurity", issuedTo="EFE",
                               notAfter=util.current_time_millis() + 720000)
        return jsonpickle.encode(token)

    @staticmethod
    def _sign(data):
        with open('test/certs/server/application.priv', 'r') as f:
            server_private_key = f.read()
        key = ossl.load_privatekey(ossl.FILETYPE_PEM, server_private_key)
        return base64.b64encode(ossl.sign(key, data, 'sha256'))

    def IT_user_info(self):
        subject = "CN=EzbakeClient, OU=42six, O=CSC, C=US"
        dn = self._make_dn(subject)
        sig = self._sign(dn)
        t = self.es_client.fetch_user_token({
            HTTP_HEADER_USER_INFO: dn,
            HTTP_HEADER_SIGNATURE: sig})

        nt.assert_equal(self.appId, t.validity.issuedTo)
        nt.assert_equal(self.appId, t.validity.issuedFor)
        nt.assert_equal(subject, t.tokenPrincipal.principal)
