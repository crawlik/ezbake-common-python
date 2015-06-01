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

import logging
import socket
import sys

def getHostname():
    return socket.gethostname()

class EzLogHandler(logging.StreamHandler):
    def __init__(self, stream = sys.stdout):
        super(self.__class__, self).__init__(stream)
        self.setFormatter(EzLogFormatter())

class EzLogFormatter(logging.Formatter):
    # defer hostname lookup until class is instantiated
    def __init__(self, fmt = None, datefmt = None):
        hostname = getHostname()
        self.defaultFormat = hostname + ' %(asctime)s [%(threadName)s] %(levelname)-5s %(name)s - %(message)s'
        if fmt is None:
            fmt = self.defaultFormat
        super(self.__class__, self).__init__(fmt, datefmt)


def ezConfig():
    """
    attach an EzLogHandler to ROOT logger

    """
    log = logging.getLogger()

    # ensure we only add one handler

    loggingConfigured = False
    for hdlr in log.handlers:
        if isinstance(hdlr, EzLogHandler):
            loggingConfigured = True
            break
    if not loggingConfigured:
        hdlr = EzLogHandler()
        log.addHandler(hdlr)
