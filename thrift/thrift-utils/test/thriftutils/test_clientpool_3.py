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
    Test the eviction functionality of client pool.
"""

import nose.tools as nt
import threading
import random
import time

from ezbake.configuration.EzConfiguration import EzConfiguration
from ezbake.configuration.helpers import ApplicationConfiguration

from ..ezpz.t import EzPz
from ..ezpz.handler import EzPzHandler

from ezbake.thrift.utils.clientpool import ThriftClientPool
from ezbake.thrift.utils.ezthrifttest import EzThriftServerTestHarness

ENDPOINTS = ["localhost:31887"]


class ThriftClientPoolTest(EzThriftServerTestHarness):

    def setUp(self):
        super(ThriftClientPoolTest, self).setUp()

        ez_props = EzConfiguration().getProperties()
        ez_props["thrift.use.ssl"] = "false"
        ez_props["zookeeper.connection.string"] = self.hosts
        ez_props["thrift.max.idle.clients"] = 6
        # ez_props["thrift.max.pool.clients"] = 6
        ez_props["thrift.millis.between.client.eviction.checks"] = 1000
        ez_props["thrift.millis.idle.before.eviction"] = 1.5 * 1000
        application_name = ApplicationConfiguration(ez_props).getApplicationName()

        for endpoint in ENDPOINTS:
            host, port = endpoint.split(':')
            self.add_server(application_name, "ezpz", host, int(port),
                            EzPz.Processor(EzPzHandler()), use_simple_server=False)

        self.clientPool = ThriftClientPool(ez_props)

    def tearDown(self):
        self.clientPool.close()
        nt.assert_false(self.clientPool._get_service_map())
        nt.assert_false(self.clientPool._get_client_map())
        super(ThriftClientPoolTest, self).tearDown()

    def client_thread(self, tid):
        print tid
        client = self.clientPool.get_client(service_name='ezpz', clazz=EzPz.Client)
        res = client.ez2(random.randint(10, 20) * 0.1)
        print chr(ord('a') + tid)
        return res

    def test_eviction(self):

        threads = []
        for i in range(10):
            thread = threading.Thread(target=self.client_thread, args=(i,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        time.sleep(3)                                   # sleep longer enough to evict all connections.
        client = self.clientPool.get_client(service_name='ezpz', clazz=EzPz.Client)
        #client._pool._connection_queue.join()           # test to see if join function on queue still work
        nt.assert_equal(0, client._pool._connection_queue.qsize())

    def client_thread_for_apps(self, tid):
        print tid
        client = self.clientPool.get_client(app_name='testApp', service_name='ezpz', clazz=EzPz.Client)
        res = client.ez2(random.randint(10, 20) * 0.1)
        print chr(ord('a') + tid)
        return res

    def test_eviction_for_apps(self):


        threads = []
        for i in range(10):
            thread = threading.Thread(target=self.client_thread, args=(i,))
            thread.start()
            threads.append(thread)

        for thread in threads:
            thread.join()

        time.sleep(3)                                   # sleep longer enough to evict all connections.
        client = self.clientPool.get_client(app_name='testApp', service_name='ezpz', clazz=EzPz.Client)
        #client._pool._connection_queue.join()           # test to see if join function on queue still work
        nt.assert_equal(0, client._pool._connection_queue.qsize())

