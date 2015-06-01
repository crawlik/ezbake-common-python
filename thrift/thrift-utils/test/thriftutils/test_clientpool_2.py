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

import nose.tools as nt

from ezbake.configuration.EzConfiguration import EzConfiguration
from ezbake.configuration.helpers import ApplicationConfiguration

from ..ezpz.t import EzPz
from ..ezpz.handler import EzPzHandler

from ezbake.thrift.utils.clientpool import ThriftClientPool
from ezbake.thrift.utils.ezthrifttest import EzThriftServerTestHarness

ENDPOINTS = ["localhost:31887"]#, "localhost:31896"]


class ThriftClientPoolTest(EzThriftServerTestHarness):

    def setUp(self):
        super(ThriftClientPoolTest, self).setUp()

        ez_props = EzConfiguration().getProperties()
        ez_props["thrift.use.ssl"] = "false"
        ez_props["zookeeper.connection.string"] = self.hosts
        application_name = ApplicationConfiguration(ez_props).getApplicationName()

        for endpoint in ENDPOINTS:
            host, port = endpoint.split(':')
            self.add_server(application_name, "ezpz", host, int(port), EzPz.Processor(EzPzHandler()))

        self.sd_client.register_endpoint(application_name, "service_one", 'localhost', 8083)
        self.sd_client.register_endpoint(application_name, "service_two", 'localhost', 8084)
        self.sd_client.register_endpoint(application_name, "service_three", 'localhost', 8085)

        self.sd_client.register_common_endpoint('common_service_one', 'localhost', 8080)
        self.sd_client.register_common_endpoint('common_service_two', 'localhost', 8081)
        self.sd_client.register_common_endpoint('common_service_three', 'localhost', 8082)
        self.sd_client.register_common_endpoint('common_service_multi', '192.168.1.1', 6060)
        self.sd_client.register_common_endpoint('common_service_multi', '192.168.1.2', 6161)

        self.sd_client.register_endpoint("NotThriftClientPool", "unknown_service_three", 'localhost', 8091)
        self.sd_client.register_endpoint("NotThriftClientPool", "unknown_service_three", 'localhost', 8092)
        self.sd_client.register_endpoint("NotThriftClientPool", "unknown_service_three", 'localhost', 8093)

        self.clientPool = ThriftClientPool(ez_props)

    def tearDown(self):
        self.clientPool.close()
        nt.assert_false(self.clientPool._get_service_map())
        nt.assert_false(self.clientPool._get_client_map())
        super(ThriftClientPoolTest, self).tearDown()

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
        client = self.clientPool.get_client(service_name='ezpz', clazz=EzPz.Client)
        try:
            nt.assert_equal('pz', client.ez())
        finally:
            client.close()

        client = self.clientPool.get_client(service_name='ezpz1', clazz=EzPz.Client)            # None existing service
        nt.assert_false(client)

    def test_multi_get_client(self):
        client1 = self.clientPool.get_client(service_name='ezpz', clazz=EzPz.Client)
        client2 = self.clientPool.get_client(service_name='ezpz', clazz=EzPz.Client)
        try:
            nt.assert_equal('pz', client1.ez())
            nt.assert_equal('pz', client2.ez())
        finally:
            self.clientPool.close()

    def test_get_client_app(self):
        client = self.clientPool.get_client(app_name="testApp", service_name="ezpz", clazz=EzPz.Client)
        try:
            nt.assert_equal("pz", client.ez())
        finally:
            client.close()

        client = self.clientPool.get_client(app_name="testApp1", service_name="ezpz0", clazz=EzPz.Client) # None existing app
        nt.assert_false(client)