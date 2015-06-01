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
#


"""
EzBake Gevent Server

Provides an EzBake Thrift Server using gevent coroutine-based handlers

Note: Your main python module should run the gevent monkey_patch
"""

import gevent
from thrift.server.TServer import TServer
from thrift.transport import TTransport


class TGeventServer(TServer):
    """
    Gevent socket implementation of TServer
    """

    def __init__(self, logger, *args):
        TServer.__init__(self, *args)
        self._logger = logger

    def handle(self, client):
        itrans = self.inputTransportFactory.getTransport(client)
        otrans = self.outputTransportFactory.getTransport(client)
        iprot = self.inputProtocolFactory.getProtocol(itrans)
        oprot = self.outputProtocolFactory.getProtocol(otrans)
        try:
            while True:
                self.processor.process(iprot, oprot)
        except TTransport.TTransportException:
            pass
        itrans.close()
        otrans.close()

    def serve(self):
        self.serverTransport.listen()
        while True:
            try:
                client = self.serverTransport.accept()
                gevent.spawn(self.handle, client)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                self._logger.exception(e)

