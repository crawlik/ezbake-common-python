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
EzThriftTest contains classes that will be useful for testing thrift services
"""
from kazoo.testing import KazooTestCase
from ezbake.discovery import ServiceDiscoveryClient

from thrift.protocol import TBinaryProtocol
from thrift.server import TServer
from thrift.transport import TSocket, TTransport
from thrift.transport.TTransport import TTransportException

from ..transport.EzSSLSocket import TSSLServerSocket

from multiprocessing.process import Process
import time
import logging
logger = logging.getLogger(__name__)


class EzThriftServerTestHarness(KazooTestCase):
    """The EzThriftServerTestHarness extends KazooTestCase to provide service discovery for clients in tests

    The thrift server is started using a TSimpleServer and registered with EzBake service discovery
    """

    def setUp(self):
        super(EzThriftServerTestHarness, self).setUp()
        self.sd_client = ServiceDiscoveryClient(self.hosts)
        self.server_processes = []

    @staticmethod
    def __thrift_server(processor, host="localhost", port=8449, use_simple_server=True,
                        use_ssl=False, ca_certs=None, cert=None, key=None):
        if use_ssl:
            transport = TSSLServerSocket(host=host, port=port,
                                         ca_certs=ca_certs, cert=cert, key=key)
        else:
            transport = TSocket.TServerSocket(host=host, port=port)
        t_factory = TTransport.TBufferedTransportFactory()
        p_factory = TBinaryProtocol.TBinaryProtocolFactory()

        if use_simple_server:
            server = TServer.TSimpleServer(processor, transport, t_factory, p_factory)
        else:
            server = TServer.TThreadedServer(processor, transport, t_factory, p_factory)

        try:
            server.serve()
            print 'server started!'
        except (Exception, AttributeError, TTransportException) as e:
            print e
            logger.error("Server error: %s", e)

    def add_server(self, app_name, service_name, host, port, processor, use_simple_server=True, wait=1,
                   use_ssl=False, ca_certs=None, cert=None, key=None):
        self.sd_client.register_endpoint(app_name, service_name, host, port)
        server_process = Process(target=self.__thrift_server,
                                 args=(processor, host, port, use_simple_server, use_ssl, ca_certs, cert, key))
        server_process.start()
        time.sleep(wait)
        self.server_processes.append(server_process)

    def tearDown(self):
        super(EzThriftServerTestHarness, self).tearDown()
        for server_process in self.server_processes:
            if server_process.is_alive():
                server_process.terminate()
