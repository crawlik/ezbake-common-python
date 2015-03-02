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

import nose.tools as nt
import threading
import random
import time
current_time_millis = lambda: int(round(time.time() * 1000))

from ezbake.thrift.utils.evictqueue import LifoQueueWithEvict

EVICT_TIME = 1500


def clean_up(obj):
    print "Object", obj.i, "is cleaned up!"


class EvictObj(object):
    """
        Object to be evicted
    """
    def __init__(self, i):
        self.i = i


class TestLifoQueueWithEvict(object):

    def setUp(self):
        self.queue = LifoQueueWithEvict(10)
        for i in range(10):
            self.queue.put((EvictObj(i), current_time_millis()))
            time.sleep(0.1)

    def test_evict_none(self):
        time.sleep(0.1)
        self.queue.evict(EVICT_TIME, clean_up)
        nt.assert_equal(10, self.queue.qsize())

    def test_evict_5(self):
        time.sleep(0.95)
        self.queue.evict(EVICT_TIME)
        nt.assert_equal(5, self.queue.qsize())

    def test_evict_all(self):
        time.sleep(2)
        self.queue.evict(EVICT_TIME, clean_up)
        nt.assert_equal(0, self.queue.qsize())

    def evict_thread(self):
        while True:
            time.sleep(1)
            self.queue.evict(EVICT_TIME, clean_up)

    def get_thread(self):
        while True:
            time.sleep(random.randint(200, 400) * 0.001)
            (obj, t) = self.queue.get()
            print obj.i, "--",t

    def test_evict_thread(self):

        thread = threading.Thread(target=self.evict_thread)
        thread.setDaemon(True)
        thread.start()

        thread = threading.Thread(target=self.get_thread)
        thread.setDaemon(True)
        thread.start()

        for i in range(10, 30):
            time.sleep(random.randint(100, 200) * 0.001)
            self.queue.put((EvictObj(i), current_time_millis()))
            print i, "is put into queue"

        time.sleep(3)                       # to ensure all object is evicted.
        # self.queue.join()                   # test to see if join function on queue still work
        nt.assert_equal(0, self.queue.qsize())