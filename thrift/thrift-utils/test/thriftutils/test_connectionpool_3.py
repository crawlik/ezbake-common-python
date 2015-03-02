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
    In this test, 3 endpoints will be given to connectionpool, but only 2 are actually started.
    This is to test the case when there is a failed connection, connection pool will try the other
    endpoint, till success. Otherwise an exception will be raised.
"""

import nose.tools as nt

from ..ezpz.t import EzPz
from ..ezpz.handler import EzPzHandler

from ezbake.thrift.utils.connectionpool import ThriftConnectionPool, PoolingThriftClient
from ezbake.thrift.utils.ezthrifttest import EzThriftServerTestHarness

ENDPOINTS = ["localhost:31891", "localhost:31892", "localhost:31893"]


class TestPool(EzThriftServerTestHarness):

    def setUp(self):
        super(TestPool, self).setUp()
        for endpoint in ENDPOINTS[1:]:                                      # first endpoint is not started.
            host, port = endpoint.split(':')
            self.add_server("testApp", "ezpz", host, int(port), EzPz.Processor(EzPzHandler()))

    def tearDown(self):
        super(TestPool, self).tearDown()

    @staticmethod
    def test_simple_pool_of_one():
        pool = ThriftConnectionPool(ENDPOINTS, EzPz.Client, size=1)
        conn = pool.get_connection()
        try:
            nt.assert_equal('pz', conn.ez())
        finally:
            pool.return_connection(conn)

    @staticmethod
    def test_client():
        pool_client = PoolingThriftClient(ENDPOINTS, EzPz.Client)
        try:
            nt.assert_equal('pz', pool_client.ez())
        finally:
            pool_client.close()