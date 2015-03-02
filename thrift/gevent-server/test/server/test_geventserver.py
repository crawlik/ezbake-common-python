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
TGeventServer UnitTests

This test case uses gevent monkey patches.
This causes KeyError exception to the thrown from the threading module at the end of the test if the threading module is loaded before gevent monkey patching
"""

import gevent.monkey; gevent.monkey.patch_all()

import nose.tools as nt

import logging
import random
import gevent

from ..ezpz.t import EzPz
from ..ezpz.handler import EzPzHandler

from thrift.protocol import TBinaryProtocol

from ezbake.thrift.server.TGeventServer import TGeventServer
from thrift.transport.TSSLSocket import TSSLServerSocket, TSSLSocket


CA_CERT = 'test/certs/server/ezbakeca.crt'
CLIENT_CRT = 'test/certs/client/application.crt'
SERVER_CRT = 'test/certs/server/application.crt'


class TestGeventServer(object):

    @classmethod
    def tearDownClass(cls):
        import thread
        import threading
        import socket
        reload(thread)
        reload(threading)
        reload(socket)

    def setUp(self):
        self.testport = random.randint(40000, 65530)
        self.server = TGeventServer(logging.getLogger(__name__),
                                    EzPz.Processor(EzPzHandler()),
                                    TSSLServerSocket(host='127.0.0.1',
                                                     port=self.testport,
                                                     certfile=SERVER_CRT))
        self.greenlet = gevent.spawn(TGeventServer.serve, self.server)

    def tearDown(self):
        gevent.killall([self.greenlet])


    def test_socketConnect(self):
        transport = TSSLSocket(host='127.0.0.1',
                               port=self.testport,
                               validate=False,
                               ca_certs=CA_CERT,
                               certfile=CLIENT_CRT)
        client = EzPz.Client(TBinaryProtocol.TBinaryProtocol(transport))
        transport.open()
        nt.eq_('pz', client.ez())


