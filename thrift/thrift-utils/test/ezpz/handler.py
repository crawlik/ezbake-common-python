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

from .t import EzPz

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import TServer

import logging
logger = logging.getLogger(__name__)

import time


class EzPzHandler(EzPz.Iface):
    def ez(self):
        return "pz"

    def ez2(self, delay):
        if delay >= 0:
            time.sleep(delay)
        return "pz2"


def start_ezpz(handler=EzPzHandler, port=28934):
    processor = EzPz.Processor(handler)
    transport = TSocket.TServerSocket(port=port)
    tfactory = TTransport.TBufferedTransportFactory()
    pfactory = TBinaryProtocol.TBinaryProtocolFactory()
    server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)
    logger.debug('Starting EzPz server on {}'.format(port))
    server.serve()


def ezpz_client(host="localhost", port=28934):
    transport = TSocket.TSocket(host, port)
    transport = TTransport.TBufferedTransport(transport)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)
    transport.open()
    return EzPz.Client(protocol)
