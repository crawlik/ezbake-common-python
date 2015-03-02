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
from ezbake.thrift.utils.ezthrifttest import EzThriftServerTestHarness
from ..ezpz.handler import EzPzHandler
from ..ezpz.t import EzPz

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

from ezbake.thrift.transport.EzSSLSocket import TSSLSocket

import nose.tools as nt


servercapath = "test/certs/server/ezbakeca.crt"
servercertpath = "test/certs/server/application.crt"
serverprivpath = "test/certs/server/application.priv"

clientcapath = "test/certs/client/ezbakeca.crt"
clientcertpath = "test/certs/client/application.crt"
clientprivpath = "test/certs/client/application.priv"

PORT = 21989
PORT_SSL = 49222


class TestEzPz(EzThriftServerTestHarness):

    def setUp(self, service_name="testApp"):
        super(TestEzPz, self).setUp()
        self.add_server("testApp", "ezpz", "localhost", PORT, EzPz.Processor(EzPzHandler()))
        self.add_server("testApp", "ezpz_ssl", "localhost", PORT_SSL, EzPz.Processor(EzPzHandler()),
                        use_ssl=True, ca_certs=servercapath, cert=servercertpath, key=serverprivpath)

    def tearDown(self):
        super(TestEzPz, self).tearDown()

    def test(self):
        endpoints = self.sd_client.get_endpoints("testApp", "ezpz")
        for endpoint in endpoints:
            host, port = endpoint.split(':')
            transport = TSocket.TSocket(host=host, port=int(port))
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            transport.open()
            client = EzPz.Client(protocol)
            nt.assert_equal('pz', client.ez())

    def test_ssl(self):
        endpoints = self.sd_client.get_endpoints("testApp", "ezpz_ssl")
        for endpoint in endpoints:
            host, port = endpoint.split(':')
            transport = TSSLSocket(host=host, port=int(port),
                                   ca_certs=clientcapath, cert=clientcertpath, key=clientprivpath)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            transport.open()
            client = EzPz.Client(protocol)
            nt.assert_equal('pz', client.ez())