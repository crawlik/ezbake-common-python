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
    LIFO queue with evict function
"""
from Queue import Queue, LifoQueue

import time
current_time_millis = lambda: int(round(time.time() * 1000))

import logging
logger = logging.getLogger(__name__)


class LifoQueueWithEvict(LifoQueue):
    """
    """
    def evict(self, idle_threshold_millis, cleanup_func=None):
        with self.mutex:
            n = -1
            curr_time = current_time_millis()
            for i, (obj, t) in enumerate(self.queue):
                if curr_time - t > idle_threshold_millis:
                    n = i
                    if cleanup_func is not None:
                        cleanup_func(obj)
            if n >= 0:
                del self.queue[0:n+1]
                logger.debug("%s objects are evicted.", str(n+1))
            else:
                return

            self.unfinished_tasks = len(self.queue)
            if self.unfinished_tasks == 0:
                self.all_tasks_done.notify()
            if self.unfinished_tasks < self.maxsize:
                self.not_full.notify()