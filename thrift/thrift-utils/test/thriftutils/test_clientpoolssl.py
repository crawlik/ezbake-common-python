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

from ..ezpz.t import EzPz
from ..ezpz.handler import EzPzHandler

from ezbake.configuration.EzConfiguration import EzConfiguration
from ezbake.configuration.helpers import ApplicationConfiguration

from ezbake.thrift.utils.clientpool import ThriftClientPool
from ezbake.thrift.utils.ezthrifttest import EzThriftServerTestHarness

servercapath = "test/certs/server/ezbakeca.crt"
servercertpath = "test/certs/server/application.crt"
serverprivpath = "test/certs/server/application.priv"

ENDPOINTS = ["localhost:31888", "localhost:31889"]


class ThriftClientPoolTest(EzThriftServerTestHarness):

    def setUp(self):
        super(ThriftClientPoolTest, self).setUp()

        ez_props = EzConfiguration().getProperties()
        ez_props["thrift.use.ssl"] = "true"
        ez_props["zookeeper.connection.string"] = self.hosts
        application_name = ApplicationConfiguration(ez_props).getApplicationName()

        for endpoint in ENDPOINTS:
            host, port = endpoint.split(':')
            self.add_server(application_name, "ezpz_ssl", host, int(port), EzPz.Processor(EzPzHandler()),
                            use_ssl=True, ca_certs=servercapath, cert=servercertpath, key=serverprivpath)

        self.clientPool = ThriftClientPool(ez_props)

    def tearDown(self):
        self.clientPool.close()
        nt.assert_false(self.clientPool._get_service_map())
        nt.assert_false(self.clientPool._get_client_map())
        super(ThriftClientPoolTest, self).tearDown()

    def test_get_client(self):
        client = self.clientPool.get_client(service_name='ezpz_ssl', clazz=EzPz.Client)
        try:
            resp = client.ez()
            nt.assert_equal('pz', resp)
        finally:
            client.close()

        client = self.clientPool.get_client(service_name='ezpz1', clazz=EzPz.Client)            # None existing service
        nt.assert_false(client)

    def test_get_client_for_apps(self):
        client = self.clientPool.get_client(app_name='testApp', service_name='ezpz_ssl', clazz=EzPz.Client)
        try:
            resp = client.ez()
            nt.assert_equal('pz', resp)
        finally:
            client.close()

        client = self.clientPool.get_client(app_name='testApp', service_name='ezpz1', clazz=EzPz.Client)            # None existing service
        nt.assert_false(client)


    def test_multi_get_client(self):
        client1 = self.clientPool.get_client(service_name='ezpz_ssl', clazz=EzPz.Client)
        client2 = self.clientPool.get_client(service_name='ezpz_ssl', clazz=EzPz.Client)
        try:
            nt.assert_equal('pz', client1.ez())
            nt.assert_equal('pz', client2.ez())
        finally:
            self.clientPool.close()

    def test_multi_get_client_for_apps(self):
        client1 = self.clientPool.get_client(app_name='testApp', service_name='ezpz_ssl', clazz=EzPz.Client)
        client2 = self.clientPool.get_client(app_name='testApp', service_name='ezpz_ssl', clazz=EzPz.Client)
        try:
            nt.assert_equal('pz', client1.ez())
            nt.assert_equal('pz', client2.ez())
        finally:
            self.clientPool.close()
