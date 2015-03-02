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
    This module is used for token eviction test
"""

import unittest
import nose.tools as nt

from ezbake.security.util import current_time_millis
from ezbake.security.client import TokenCache, sleep_millis

from threading import Thread


class TestTokenCacheEvict(unittest.TestCase):

    def setUp(self):
        tc = TokenCache()
        tc.clear()                                          # singleton need to be cleared for each test

    def test_behaves_like_dict(self):
        a = TokenCache(one=1, two=2, three=3)
        b = TokenCache(zip(['one', 'two', 'three'], [1, 2, 3]))
        c = TokenCache([('two', 2), ('one', 1), ('three', 3)])
        d = TokenCache({'three': 3, 'one': 1, 'two': 2})
        nt.assert_true(a == b == c == d)

    def test_singleton(self):
        token_cache1 = TokenCache(100)
        token_cache2 = TokenCache(200)
        nt.assert_equal(token_cache1, token_cache2)
        token_cache1['key'] = (current_time_millis() + 10000, 'token')
        nt.assert_equal('token', token_cache2['key'])

    def thread_1(self):
        cache = TokenCache()
        sleep_millis(200)
        cache['key'] = (current_time_millis()+1000, 'token')
        sleep_millis(400)

    def thread_2(self):
        cache = TokenCache()
        sleep_millis(400)
        nt.assert_equal('token', cache['key'])
        sleep_millis(400)

    def test_singleton_among_threads(self):
        thread1 = Thread(target=self.thread_1)
        thread2 = Thread(target=self.thread_2)
        thread1.start()
        thread2.start()
        thread1.join()
        thread2.join()

        sleep_millis(100)
        cache = TokenCache()
        nt.assert_equal('token', cache['key'])

    def test_expires(self):
        get_cached_token = lambda k: token_cache[k]
        token_cache = TokenCache()
        token_cache['key'] = (current_time_millis() + 500, 'token')
        sleep_millis(300)
        token = get_cached_token('key')
        nt.assert_equal('token', token)
        sleep_millis(300)
        nt.assert_equal(1, len(token_cache))                                 # token still in cache, but expired
        nt.assert_raises(KeyError, get_cached_token, 'key')

    def test_evict(self):
        token_cache = TokenCache(500)
        get_cached_token = lambda k: token_cache[k]
        token_cache['key'] = (current_time_millis() + 800, 'token')         # longer enough to pass 1st evict

        sleep_millis(300)                                                   # before 1st evict
        nt.assert_equal('token', get_cached_token('key'))

        sleep_millis(300)                                                   # short enough so not expired
        nt.assert_equal('token', get_cached_token('key'))                   # 1st eviction will not delete

        sleep_millis(600)
        nt.assert_equal(0, len(token_cache))                                # token was evicted in 2nd round.
        nt.assert_raises(KeyError, get_cached_token, 'key')