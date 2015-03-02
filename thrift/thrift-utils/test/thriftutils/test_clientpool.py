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

import time
from multiprocessing import Process
import nose.tools as nt
from kazoo.testing import KazooTestCase

from ezbake.configuration.EzConfiguration import EzConfiguration
from ezbake.configuration.helpers import ApplicationConfiguration

from ..ezpz.t import EzPz
from ..ezpz.handler import EzPzHandler, start_ezpz

from ezbake.thrift.utils.clientpool import ThriftClientPool
from ezbake.discovery import ServiceDiscoveryClient

ENDPOINTS = ["localhost:31885", "localhost:31886"]


class ThriftClientPoolTest(KazooTestCase):

    def setUp(self):
        """
        """
        super(ThriftClientPoolTest, self).setUp()
        ezd_client = ServiceDiscoveryClient(self.hosts)

        ez_props = EzConfiguration().getProperties()
        ez_props["thrift.use.ssl"] = "false"
        ez_props["zookeeper.connection.string"] = self.hosts
        application_name = ApplicationConfiguration(ez_props).getApplicationName()

        self.serverProcesses = []
        for endpoint in ENDPOINTS:
            host, port = endpoint.split(':')
            port = int(port)
            server_process = Process(target=start_ezpz, args=(EzPzHandler(), port,))
            server_process.start()
            time.sleep(1)
            self.serverProcesses.append(server_process)
            ezd_client.register_endpoint(application_name, "ezpz", host, port)

        ezd_client.register_endpoint(application_name, "service_one", 'localhost', 8083)
        ezd_client.register_endpoint(application_name, "service_two", 'localhost', 8084)
        ezd_client.register_endpoint(application_name, "service_three", 'localhost', 8085)

        ezd_client.register_common_endpoint('common_service_one', 'localhost', 8080)
        ezd_client.register_common_endpoint('common_service_two', 'localhost', 8081)
        ezd_client.register_common_endpoint('common_service_three', 'localhost', 8082)
        ezd_client.register_common_endpoint('common_service_multi', '192.168.1.1', 6060)
        ezd_client.register_common_endpoint('common_service_multi', '192.168.1.2', 6161)

        ezd_client.register_endpoint("NotThriftClientPool", "unknown_service_three", 'localhost', 8091)
        ezd_client.register_endpoint("NotThriftClientPool", "unknown_service_three", 'localhost', 8092)
        ezd_client.register_endpoint("NotThriftClientPool", "unknown_service_three", 'localhost', 8093)

        self.clientPool = ThriftClientPool(ez_props)

    def tearDown(self):
        super(ThriftClientPoolTest, self).tearDown()
        self.clientPool.close()
        nt.assert_false(self.clientPool._get_service_map())
        nt.assert_false(self.clientPool._get_client_map())
        for server_process in self.serverProcesses:
            if server_process.is_alive():
                server_process.terminate()

    def test_endpoints(self):
        service_map = self.clientPool._get_service_map()
        self.assertTrue("common_service_one" in service_map)
        self.assertTrue("common_service_two" in service_map)
        self.assertTrue("common_service_three" in service_map)
        self.assertTrue("service_one" in service_map)
        self.assertTrue("service_two" in service_map)
        self.assertTrue("service_three" in service_map)
        self.assertFalse("unknown_service_one" in service_map)
        self.assertFalse("unknown_service_two" in service_map)
        self.assertFalse("unknown_service_three" in service_map)

        self.assertTrue("common_service_multi" in service_map)
        self.assertEqual(len(service_map["common_service_multi"]), 2)

        self.assertTrue("ezpz" in service_map)
        self.assertEqual(len(service_map["ezpz"]), len(ENDPOINTS))

    def test_get_client(self):
        client = self.clientPool.get_client('ezpz', EzPz.Client)
        try:
            nt.assert_equal('pz', client.ez())
        finally:
            client.close()

        client = self.clientPool.get_client('ezpz1', EzPz.Client)            # None existing service
        nt.assert_false(client)

    def test_multi_get_client(self):
        client1 = self.clientPool.get_client('ezpz', EzPz.Client)
        client2 = self.clientPool.get_client('ezpz', EzPz.Client)
        try:
            nt.assert_equal('pz', client1.ez())
            nt.assert_equal('pz', client2.ez())
        finally:
            client1.close()
            client2.close()