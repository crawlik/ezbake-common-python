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

""" Register and locate services within ezDiscovery. """

import optparse
import sys
import time

from threading import RLock
from kazoo.client import KazooClient, NoNodeError

current_time_sec = lambda: int(round(time.time()))


class EphimeralDict(dict):

    _instance = None
    _rlock = RLock()

    def __new__(cls, *args, **kwargs):
        """
        Create the cache as a singleton.

        :param cls:
        :param args:
        :param kwargs:
        :return:
        """
        with cls._rlock:
            if getattr(cls, '_instance', None) is None:
                cls._instance = super(EphimeralDict, cls).\
                    __new__(cls, *args, **kwargs)

        return cls._instance

    def __init__(self, ttl_secs=1200, *args, **kwargs):
        """
        Initializes ExpiringCache
        :param ttl_secs:
        :return:
        """
        super(EphimeralDict, self).__init__(*args, **kwargs)

        self.ttl_secs = ttl_secs if not hasattr(self, 'ttl_secs') else self.ttl_secs
        self._expires = getattr(self, '_expires', {})
        self.rlock = self.__class__._rlock


    def __setitem__(self, key, value):
        """
        Set the value for the given key in the cache. Sets the key with the
        ttl.

        :param key:
        :param value:
        :return:
        """
        with self.rlock:
            self._expires[key] = current_time_sec() + self.ttl_secs
            super(EphimeralDict, self).__setitem__(key, value)

    def __getitem__(self, key):
        """
        Get the value for the key in the cache.

        :param key:
        :return:
        """
        self.prune(key)
        return super(EphimeralDict, self).__getitem__(key)


    def __contains__(self, k):
        """
        Checks if item is in queue.

        :param k:
        :return:
        """
        try:
            self.prune(k)
        except KeyError:
            pass

        return super(EphimeralDict, self).__contains__(k)

    def __delitem__(self, key):
        """
        Deletes the key from the dictionary.

        :param key:
        :return:
        """
        with self.rlock:
            del self._expires[key]
            super(EphimeralDict, self).__delitem__(key)

    def prune(self, key):
        """
        Prunes the inner data dictionary to ensure the ephimeral nature of the
        class. It raises a KeyError if the given key is not in the data
        dictionary.

        :param key:
        :return:
        """

        # determine if the key has expired
        with self.rlock:
            expires_ts = self._expires[key]
            if expires_ts < current_time_sec():
                del self[key]


    def clear(self):
        """
        Clears the dictionary
        :return:
        """
        with self.rlock:
            for k in self.keys():
                del self[k]

    def clean(self):
        """
        Cleans the contents of the dictionary, and starts from scratch.
        """
        del self.__class__._instance
        EphimeralDict()





class ServiceDiscoveryClient:
    NAMESPACE = 'ezDiscovery'
    COMMON_APP_NAME = 'common_services'
    ENDPOINTS = 'endpoints'
    SECURITY = 'security'
    SECURITY_ID = 'security_id'

    def __init__(self, hosts='localhost:2181'):
        self.hosts = hosts
        self.securityIdCache = EphimeralDict(1000)

    def _connect(self):
        """Create a connection to Zookeeper for use in discovery calls."""
        zk = KazooClient(hosts=self.hosts)
        zk.start()
        return zk

    @staticmethod
    def _disconnect(zk):
        """Disconnect from Zookeeper if there is a connection."""
        if zk:
            zk.stop()
            zk.close()

    def register_endpoint(self, app_name, service_name, host, port):
        """Register an endpoint with Zookeeper."""
        zk = self._connect()
        try:
            zk.ensure_path('/'.join([
                self.NAMESPACE,
                app_name,
                service_name,
                self.ENDPOINTS,
                host + ':' + str(port)
            ]))
        finally:
            self._disconnect(zk)

    def register_common_endpoint(self, service_name, host, port):
        """Register a common endpoint under the default application name."""
        self.register_endpoint(self.COMMON_APP_NAME, service_name, host, port)

    def _recurse_deletion(self, zk, path_parts):
        """Moves up the tree of the given path parts deleting if empty.

        NOTE: Will not delete path from root to endpoints (inclusively).
        """
        if len(path_parts) > 4:
            path = '/'.join(path_parts)
            if zk.exists(path) and not len(zk.get_children(path)):
                zk.delete(path)
                self._recurse_deletion(zk, path_parts[:-1])

    def unregister_endpoint(self, app_name, service_name, host, port):
        """Unregister and endpoint with Zookeeper."""
        zk = self._connect()
        try:
            self._recurse_deletion(zk, [
                self.NAMESPACE,
                app_name,
                service_name,
                self.ENDPOINTS,
                host + ':' + str(port)
            ])
        finally:
            self._disconnect(zk)

    def unregister_common_endpoint(self, service_name, host='localhost',
                                   port=2181):
        """Unregister a common endpoint under the default application name."""
        self.unregister_endpoint(self.COMMON_APP_NAME, service_name, host,
                                 port)

    def _get_children(self, path):
        """Shortcut method to return the children on the given path."""
        zk = self._connect()
        children = []
        try:
            if zk.exists(path):
                children = zk.get_children(path)
        finally:
            self._disconnect(zk)
        return children

    def get_applications(self):
        """Get a list of applications registered in Zookeeper."""
        return self._get_children(self.NAMESPACE)

    def get_services(self, app_name):
        """Get a list services by the given application name."""
        return self._get_children('/'.join([self.NAMESPACE, app_name]))

    def get_common_services(self):
        """Get a list services under the common application name."""
        return self.get_services(self.COMMON_APP_NAME)

    def get_endpoints(self, app_name, service_name):
        """Get a list of endpoints by the given application and service name."""
        return self._get_children(
            '/'.join([self.NAMESPACE, app_name, service_name, self.ENDPOINTS])
        )

    def get_common_endpoints(self, service_name):
        """Get a list of endpoints from the common application name and given
        service name.
        """
        return self.get_endpoints(self.COMMON_APP_NAME, service_name)

    def is_service_common(self, service_name):
        """Checks if the given service name is in the common services application.

        NOTE: Returns false if the service does not exist.
        """
        zk = self._connect()
        try:
            result = bool(zk.exists('/'.join([
                self.NAMESPACE,
                self.COMMON_APP_NAME,
                service_name
            ])))
        finally:
            self._disconnect(zk)
        return result

    def set_security_id_for_application(self, app_name, security_id):
        """Set the security id for the given application."""
        zk = self._connect()
        try:
            path = '/'.join([
                self.NAMESPACE,
                app_name,
                self.SECURITY,
                self.SECURITY_ID
            ])
            zk.ensure_path(path)
            zk.set(path, security_id)
        finally:
            self._disconnect(zk)

    def get_security_id(self, target):
        """
        Given a app or common service name as target, this method determines if
        the name is a common service or an applicaiton, and gets
        the appropriate security id for it.

        :param name: app name or common service name
        :return: security_id
        """
        if self.is_service_common(target):
            target = '/'.join([self.COMMON_APP_NAME, target])

        # return security id from cache if it exists
        if target in self.securityIdCache:
            return self.securityIdCache[target]

        zk = self._connect()
        result = None
        try:
            result = zk.get('/'.join([
                self.NAMESPACE,
                target,
                self.SECURITY,
                self.SECURITY_ID
            ]))[0]
            self.securityIdCache[target] = result
        except NoNodeError:
            pass
        finally:
            self._disconnect(zk)
        return result

    def set_security_id_for_common_service(self, service_name, security_id):
        """Set the security id for the given common service."""
        self.set_security_id_for_application(
            '/'.join([self.COMMON_APP_NAME, service_name]),
            security_id
        )

    ACTIONS = {
        'register': {
            'args': [5, 'Must provide app name, service name, host and port.'],
            'method': register_endpoint
        },
        'register-common-services': {
            'args': [4, 'Must provide service name, host and port.'],
            'method': register_common_endpoint
        },
        'unregister': {
            'args': [5, 'Must provide app name, service name, host and port.'],
            'method': unregister_endpoint
        },
        'unregister-common-services': {
            'args': [4, 'Must provide service name, host and port.'],
            'method': unregister_common_endpoint
        },
        'list-applications': {
            'method': get_applications
        },
        'list-services': {
            'args': [2, 'Must provide an app name.'],
            'method': get_services
        },
        'list-common-services': {
            'method': get_common_services
        },
        'list-endpoints': {
            'args': [3, 'Must provide app name, service name.'],
            'method': get_endpoints
        },
        'list-common-endpoints': {
            'args': [2, 'Must provide a common service name.'],
            'method': get_common_endpoints
        },
        'is-service-common': {
            'args': [2, 'Must provide a service name.'],
            'method': is_service_common
        },
        'application-set-security-id': {
            'args': [3, 'Must provide an app name and security id.'],
            'method': get_security_id
        },
        'application-get-security-id': {
            'args': [2, 'Must provide an app name.'],
            'method': get_security_id
        },
        'common-service-set-security-id': {
            'args': [3, 'Must provide a service name and security id.'],
            'method': set_security_id_for_common_service
        },
        'common-service-get-security-id': {
            'args': [2, 'Must provide a service name.'],
            'method': get_security_id
        },
    }

    def exec_cmd_line(self, args):
        """
        execute command line
        """
        action = args[0]
        if action in self.ACTIONS:
            action = self.ACTIONS[action]
            if 'args' in action:
                _arg_count(args, action['args'][0], action['args'][1])
            method_args = [self] + args[1:]
            result = action['method'](*method_args)
            if result is not None:  # Some commands return a boolean.
                if isinstance(result, list):
                    for i in result:
                        print i
                else:
                    print result
        else:
            print 'Invalid action: ' + action
            sys.exit(1)


def _arg_count(args, number, message='Invalid arguments.'):
    """Counts the arguments given and exits with failed status if needed.

    Really just a convenience method for the main method, not part of the
    discovery API.
    """
    if len(args) < number:
        print message
        sys.exit(1)


def invalid_action(action=''):
    """Prints an error message and exits."""
    if action:
        print 'Invalid action: ' % action
    else:
        print 'Action not specified.'
    sys.exit(1)


def main():
    """Module will act as a command line utility if not imported as a module in
    another application.
    """
    parser = optparse.OptionParser(
        usage='usage: %prog [options] ACTION arg1 arg2 ...'
    )
    parser.add_option(
        '-z',
        '--zookeeper',
        default='localhost:2181',
        help='Zookeeper location (host:port).'
    )
    options, args = parser.parse_args()

    if not args:
        invalid_action()

    ServiceDiscoveryClient(options.zookeeper).exec_cmd_line(args)


if __name__ == '__main__':
    main()
