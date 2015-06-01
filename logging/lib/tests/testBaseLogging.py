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

from pkg_resources import resource_filename
import nose.tools as nt

import logging
import os
import shutil
import socket
import tempfile
import time
import unittest

from ezbake import ezlogging


class TestLogging(unittest.TestCase):

    def setUp(self):
        self.tmpDir = tempfile.mkdtemp()
        self.origSocketGethostname = socket.gethostname
        socket.gethostname = lambda: "testsuite"

        self.origTime = time.time
        time.time = lambda: 0

        # force time zone to UTC so tests are consistent
        self.tz = os.getenv('TZ')
        os.environ['TZ'] = 'UTC'
        time.tzset()

    def tearDown(self):
        socket.gethostname = self.origSocketGethostname
        time.time = self.origTime
        if self.tz is None:
            os.unsetenv('TZ')
        else:
            os.environ['TZ'] = self.tz
        time.tzset()
        shutil.rmtree(self.tmpDir, ignore_errors=True)
        log = logging.getLogger()
        for hdlr in log.handlers[:]:
            if isinstance(hdlr, ezlogging.EzLogHandler):
                log.removeHandler(hdlr)

    def testLoggingLoadedTwice(self):
        # handlers can exist from such mechanisms as the test suite, so it's not necessarily empty
        # make a list of existing handlers so they can be ignored
        hdlrsBefore = logging.getLogger().handlers[:]
        ezlogging.ezConfig()
        ezlogging.ezConfig()
        hdlrs = [x for x in logging.getLogger().handlers if x not in hdlrsBefore]
        nt.eq_(len(hdlrs), 1)

    def testLogFormat(self):
        # file like objects will close their descriptors on cleanup. this will not leak
        # be mindful that we're buffering into a pipe and then reading in same thread. kernel limits (64K?) apply
        rdfd, wrfd = os.pipe()
        rd = os.fdopen(rdfd, 'r')
        wr = os.fdopen(wrfd, 'w')
        hdlr = ezlogging.EzLogHandler(wr)
        log = logging.getLogger()
        log.addHandler(hdlr)
        logging.warning('test')
        line = rd.readline()
        nt.eq_(line, 'testsuite 1970-01-01 00:00:00,000 [MainThread] WARNING root - test\n')

