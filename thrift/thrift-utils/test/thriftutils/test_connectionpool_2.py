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

# -*- coding: utf-8 -*-
"""
Created on Mon Apr 14 11:59:46 2014

@author: jhastings
"""

import nose.tools as nt
from thrift.Thrift import TException

from ..ezpz.t import EzPz
from ..ezpz.handler import EzPzHandler, ezpz_client

from ezbake.thrift.utils.connectionpool import ThriftConnectionPool, PoolingThriftClient
from ezbake.thrift.utils.ezthrifttest import EzThriftServerTestHarness

PORT = 31894
ENDPOINTS = ["localhost:" + str(PORT)]


class TestPool(EzThriftServerTestHarness):

    def setUp(self):
        super(TestPool, self).setUp()
        self.add_server("testApp", "ezpz", "localhost", PORT, EzPz.Processor(EzPzHandler()))

    def tearDown(self):
        super(TestPool, self).tearDown()

    @staticmethod
    def test_ezpz_no_pool():
        client = ezpz_client(port=PORT)
        try:
            nt.assert_equal('pz', client.ez())
        finally:
            try:
                client._iprot.trans.close()
            except TException:
                pass
            try:
                client._oprot.trans.close()
            except TException:
                pass

    @staticmethod
    def test_simple_pool_of_one():
        pool = ThriftConnectionPool(ENDPOINTS, EzPz.Client, size=1)
        conn = pool.get_connection()
        try:
            nt.assert_equal('pz', conn.ez())
        finally:
            pool.return_connection(conn)

    @staticmethod
    def test_semaphore_behavior():
        pool = ThriftConnectionPool(ENDPOINTS, EzPz.Client, 1)
        conn = pool.get_connection()
        nt.assert_equal(0, pool._semaphore._Semaphore__value)
        try:
            nt.assert_equal('pz', conn.ez())
        finally:
            pool.return_connection(conn)
            nt.assert_equal(1, pool._semaphore._Semaphore__value)

    @staticmethod
    def test_queuing_behavior():
        pool = ThriftConnectionPool(ENDPOINTS, EzPz.Client, 1)
        conn = pool.get_connection()
        nt.assert_equal(0, pool._connection_queue.qsize())
        try:
            nt.assert_equal('pz', conn.ez())
        finally:
            pool.return_connection(conn)
            nt.assert_equal(1, pool._connection_queue.qsize())

    @staticmethod
    def test_client():
        pool_client = PoolingThriftClient(ENDPOINTS, EzPz.Client)
        try:
            nt.assert_equal('pz', pool_client.ez())
        finally:
            pool_client.close()