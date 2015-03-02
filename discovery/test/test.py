#!/usr/bin/env python
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

""" Unit Test for ServiceDiscoveryClient """

import getpass
import os
import time

import unittest
from kazoo.testing import KazooTestCase
from ezbake.discovery import ServiceDiscoveryClient, EphimeralDict


class ServiceDiscoveryClientTest(KazooTestCase):
    """Basic set of tests for ServiceDiscoveryClient."""

    def setUp(self):
        """Replace the Zookeeper client on the module."""
        super(ServiceDiscoveryClientTest, self).setUp()
        self.ezDiscovery = ServiceDiscoveryClient(self.hosts)

    def tearDown(self):
        """Clean up the Zookeeper entries."""
        super(ServiceDiscoveryClientTest, self).tearDown()

    def test_register_endpoint(self):
        """Register an endpoint and make sure it ends up in Zookeeper."""
        self.ezDiscovery.register_endpoint('foo', 'bar', 'localhost', 8080)
        endpoints = self.ezDiscovery.get_endpoints("foo", "bar")
        self.assertEqual(endpoints[0], "localhost:8080")

    def test_register_common_endpoint(self):
        """Register a common endpoint and make sure it ends up in Zookeeper."""
        self.ezDiscovery.register_common_endpoint('bar', 'localhost', 8080)
        endpoints = self.ezDiscovery.get_common_endpoints("bar")
        self.assertEqual(endpoints[0], "localhost:8080")

    def test_unregister_endpoint(self):
        """Register and unregister an endpoint and make sure it is gone."""
        self.ezDiscovery.register_endpoint('foo', 'bar', 'localhost', 8080)
        self.ezDiscovery.unregister_endpoint('foo', 'bar', 'localhost', 8080)
        endpoints = self.ezDiscovery.get_endpoints("foo", "bar")
        self.assertEqual(len(endpoints), 0)

    def test_unregister_common_endpoint(self):
        """Register and unregister a common endpoint and make sure it is gone. """
        self.ezDiscovery.register_common_endpoint('bar', 'localhost', 8080)
        self.ezDiscovery.unregister_common_endpoint('bar', 'localhost', 8080)
        endpoints = self.ezDiscovery.get_common_endpoints("bar")
        self.assertEqual(len(endpoints), 0)

    def test_unregister_none_exist_endpoint(self):
        """ make sure no exception is raised """
        self.ezDiscovery.unregister_endpoint('foo', 'bar', 'localhost', 8000)

    def test_unregister_multiple_endpoints(self):
        """Test that when multiple endpoints get made and some removed the tree
        of endpoints stays correct.
        """
        self.ezDiscovery.register_endpoint('foo', 'bar', 'localhost', 8000)
        self.ezDiscovery.register_endpoint('foo', 'bar', 'localhost', 8888)

        # Unregister the first endpoint.
        self.ezDiscovery.unregister_endpoint('foo', 'bar', 'localhost', 8000)
        endpoints = self.ezDiscovery.get_endpoints('foo', 'bar')
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0], 'localhost:8888')

        # Unregister the second endpoint.
        self.ezDiscovery.unregister_endpoint('foo', 'bar', 'localhost', 8888)
        endpoints = self.ezDiscovery.get_endpoints('foo', 'bar')
        self.assertEqual(len(endpoints), 0)

        base_path = '/'.join([
            ServiceDiscoveryClient.NAMESPACE,
            'foo',
            'bar',
            ServiceDiscoveryClient.ENDPOINTS
        ])
        self.assertTrue(self.client.exists(base_path))

    def test_get_applications(self):
        """Test application list."""
        # Create a few application endpoints.
        self.ezDiscovery.register_endpoint('foo', 'bar', 'localhost', 8000)
        self.ezDiscovery.register_endpoint('harry', 'sally', 'localhost', 8080)
        self.assertEqual(2, len(self.ezDiscovery.get_applications()))

    def test_get_services(self):
        """Test the application services list."""
        # Create a few application endpoints.
        self.ezDiscovery.register_endpoint('foo', 'bar', 'localhost', 8000)
        self.ezDiscovery.register_endpoint('foo', 'baz', 'localhost', 8001)
        self.ezDiscovery.register_endpoint('harry', 'sally', 'localhost', 8080)

        # Make sure it returns the right count for a single service.
        self.assertEqual(2, len(self.ezDiscovery.get_services('foo')))

        self.assertEqual(1, len(self.ezDiscovery.get_services('harry')))
        self.assertEqual('sally', self.ezDiscovery.get_services('harry')[0])

    def test_get_common_services(self):
        """Test fetching common services."""
        # Make a few common services and and an external, ensure they return
        # properly.
        self.ezDiscovery.register_common_endpoint('foo', 'localhost', 8000)
        self.ezDiscovery.register_common_endpoint('bar', 'localhost', 8001)
        self.ezDiscovery.register_endpoint('harry', 'sally', 'localhost', 8080)
        self.assertEqual(2, len(self.ezDiscovery.get_common_services()))

    def test_get_endpoints(self):
        """Test endpoint list fetching."""
        # Create a few application endpoints.
        self.ezDiscovery.register_endpoint('foo', 'bar', 'localhost', 8000)
        self.ezDiscovery.register_endpoint('foo', 'bar', 'localhost', 8001)
        self.ezDiscovery.register_endpoint('harry', 'sally', 'localhost', 8080)
        self.assertEqual(2, len(self.ezDiscovery.get_endpoints('foo', 'bar')))

    def test_get_common_endpoints(self):
        """Test fetching common endpoints."""
        # Create a few common endpoints and one not, test results.
        self.ezDiscovery.register_common_endpoint('foo', 'localhost', 8000)
        self.ezDiscovery.register_common_endpoint('foo', 'localhost', 8001)
        self.ezDiscovery.register_endpoint('harry', 'sally', 'localhost', 8080)
        self.assertEqual(2, len(self.ezDiscovery.get_common_endpoints('foo')))
        self.assertEquals(0, len(self.ezDiscovery.get_common_endpoints('sally')))

    def test_is_service_common(self):
        """Ensure only common services return true."""
        # Test one that does not exist.
        self.assertFalse(self.ezDiscovery.is_service_common('foo'))
        self.ezDiscovery.register_common_endpoint('foo', 'localhost', 8000)
        self.assertTrue(self.ezDiscovery.is_service_common('foo'))
        self.ezDiscovery.register_endpoint('harry', 'sally', 'localhost', 8080)
        self.assertFalse(self.ezDiscovery.is_service_common('sally'))

    def test_set_security_id_for_application(self):
        """Ensure security id's get set for applications."""
        self.ezDiscovery.register_endpoint('foo', 'bar', 'localhost', 8000)
        self.ezDiscovery.set_security_id_for_application('foo', 'sid')

        path = '/'.join([
            ServiceDiscoveryClient.NAMESPACE,
            'foo',
            ServiceDiscoveryClient.SECURITY,
            ServiceDiscoveryClient.SECURITY_ID
        ])
        self.assertTrue(self.client.exists(path))
        self.assertEquals('sid', self.client.get(path)[0])

    def test_set_security_id_for_common_service(self):
        """Ensure security id's get set for common services."""
        self.ezDiscovery.register_common_endpoint('foo', 'localhost', 8000)
        self.ezDiscovery.set_security_id_for_common_service('foo', 'sid')
        path = '/'.join([
            ServiceDiscoveryClient.NAMESPACE,
            '/'.join([ServiceDiscoveryClient.COMMON_APP_NAME, 'foo']),
            ServiceDiscoveryClient.SECURITY,
            ServiceDiscoveryClient.SECURITY_ID
        ])
        self.assertTrue(self.client.exists(path))
        self.assertEquals('sid', self.client.get(path)[0])

    def test_get_security_id_for_application(self):
        """Ensure fetching application security id's returns properly."""
        # Fetch one that does not exist.
        self.assertEquals(
            None,
            self.ezDiscovery.get_security_id('foo')
        )
        self.ezDiscovery.register_endpoint('foo', 'bar', 'localhost', 8000)
        self.ezDiscovery.set_security_id_for_application('foo', 'sid')
        self.assertEquals(
            'sid',
            self.ezDiscovery.get_security_id('foo')
        )

    def test_get_security_id_for_common_service(self):
        """Ensure fetching application security id's returns properly."""

        # clear the cache
        self.ezDiscovery.securityIdCache.clear()

        # Fetch one does not exist.
        self.assertEquals(
            None,
            self.ezDiscovery.get_security_id('foo')
        )
        self.ezDiscovery.register_common_endpoint('foo', 'localhost', 8000)
        self.ezDiscovery.set_security_id_for_common_service('foo', 'sid')
        self.assertEquals(
            'sid',
            self.ezDiscovery.get_security_id('foo')
        )

class EphimeralDictTestCase(unittest.TestCase):

    def setUp(self):

        self.ttl_secs = 5
        self.dict = EphimeralDict(ttl_secs=self.ttl_secs)

    def tearDown(self):

        self.dict = None


    def test_set_and_get(self):
        """
        Tests if setting items into the EphimeralDict, and getting it works
        as intended.
        """
        self.dict['a'] = 'foo'
        self.dict['b'] = 'bar'
        self.dict['c'] = 'baz'

        self.assertEqual('foo', self.dict['a'])
        self.assertEqual('bar', self.dict['b'])
        self.assertEqual('baz', self.dict['c'])

    def test_singleton(self):

        first_dict = EphimeralDict(ttl_secs=self.ttl_secs)
        first_dict['a'] = 'foo'

        del first_dict
        second_dict = EphimeralDict(ttl_secs=self.ttl_secs)
        self.assertEqual('foo', second_dict['a'])


    def test_set_and_contains(self):
        """
        Tests if setting items into the EphimeralDict and calling the 'in'
        operator works as intended.
        """

        self.dict['a'] = 'foo'
        self.dict['b'] = 'bar'

        self.assertTrue('a' in self.dict)
        self.assertTrue('b' in self.dict)
        self.assertTrue('c' not in self.dict)

    def test_clear(self):
        """
        Tests EphimeralDict.clear.
        """

        self.dict['a'] = 'foo'
        self.dict['b'] = 'bar'
        self.dict['c'] = 'baz'

        self.assertEqual('foo', self.dict['a'])
        self.assertEqual('bar', self.dict['b'])
        self.assertEqual('baz', self.dict['c'])

        self.dict.clear()
        self.assertTrue('a' not in self.dict)
        self.assertTrue('b' not in self.dict)
        self.assertTrue('c' not in self.dict)

    def test_prune(self):
        """
        Tests EphimeralDict.prune.
        """
        dict = EphimeralDict(ttl_secs=self.ttl_secs)
        dict['a'] = 'foo'
        dict['b'] = 'bar'
        dict['c'] = 'baz'

        # test that prune is not called before items' ttl was expired
        time.sleep(2)
        self.assertTrue('a' in dict)
        self.assertTrue('b' in dict)
        self.assertTrue('c' in dict)

        # test that prune is called after items' ttl has expired
        time.sleep(4)
        self.assertTrue('a' not in dict)
        self.assertTrue('b' not in dict)
        self.assertTrue('c' not in dict)

    def test_initialization(self):
        """
        Tests that the EphimeralDict is only configured once.
        """
        a = EphimeralDict(ttl_secs=self.ttl_secs)
        b = EphimeralDict(ttl_secs=self.ttl_secs * 2)
        self.assertEqual(a, b)
        self.assertEqual(a.ttl_secs, 5)
        self.assertEqual(a.ttl_secs, b.ttl_secs)






if __name__ == '__main__':
    # You may need to modify this environment variable to locate Zookeeper.
    if 'ZOOKEEPER_PATH' not in os.environ:
        os.environ['ZOOKEEPER_PATH'] = os.sep + os.path.join(
            'home',
            getpass.getuser(),
            '.ez_dev',
            'zookeeper'
        )
    unittest.main()
