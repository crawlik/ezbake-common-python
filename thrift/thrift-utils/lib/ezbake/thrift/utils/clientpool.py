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
"""

import logging
import threading
import time

from ezbake.discovery import ServiceDiscoveryClient
from ezbake.configuration.helpers import (ApplicationConfiguration, SecurityConfiguration, ThriftConfiguration,
                                          ZookeeperConfiguration)
from .connectionpool import PoolingThriftClient
from thrift.Thrift import TException


class ThriftClientPool(object):
    """
    """
    def __init__(self, ez_props):
        if ez_props is None:
            raise Exception("Invalid EzProperties.")

        zk_con_str = ZookeeperConfiguration(ez_props).getZookeeperConnectionString()
        self.ezd_client = ServiceDiscoveryClient(zk_con_str)

        self.__applicationConfiguration = ApplicationConfiguration(ez_props)
        self.__applicationName = self.__applicationConfiguration.getApplicationName()
        self.__securityConfiguration = SecurityConfiguration(ez_props)
        self.__thriftConfiguration = ThriftConfiguration(ez_props)

        self.__rLock = threading.RLock()
        self.__serviceMap = {}
        self.__clientMap = {}

        self.__log = logging.getLogger(__name__)

        if self.__applicationName is None:
            self.__log.warn("No application name was found. Only common services will be discoverable.")
        else:
            self.__log.info("Application name: " + self.__applicationName)

        try:
            self.__common_services = list(self.ezd_client.get_common_services())
        except Exception:
            self.__log.error("Unable to get common services")
            raise

        self.__refresh_end_points()
        self.__refresh_common_endpoints()

        thread = threading.Thread(target=self._evict_daemon)
        thread.setDaemon(True)
        thread.start()

    def _evict_daemon(self):
        check_interval_millis = self.__thriftConfiguration.getMillisBetweenClientEvictionChecks()
        idle_threshold_millis = self.__thriftConfiguration.getMillisIdleBeforeEviction()
        while True:
            time.sleep(check_interval_millis * 0.001)
            with self.__rLock:
                for client in self.__clientMap.itervalues():
                    client._pool.evict_check(idle_threshold_millis)

    def _get_service_map(self):
        return self.__serviceMap

    def _get_client_map(self):
        return self.__clientMap

    def __refresh_end_points(self):
        if (self.__applicationName is not None) and (self.__applicationName != ''):
            try:
                for service in self.ezd_client.get_services(self.__applicationName):
                    try:
                        endpoints = self.ezd_client.get_endpoints(self.__applicationName, service)
                        self._add_endpoints(service, endpoints)
                    except Exception:
                        self.__log.warn("No " + service + " for application " + self.__applicationName + " was found")
            except Exception:
                self.__log.warn(
                    "Failed to get application services. "
                    "This might be okay if the application hasn't registered any services."
                )

    def __refresh_common_endpoints(self):
        try:
            for service in self.ezd_client.get_common_services():
                try:
                    endpoints = self.ezd_client.get_common_endpoints(service)
                    self._add_endpoints(service, endpoints)
                except Exception:
                    self.__log.warn("No common service " + service + " was found.")
        except Exception:
            self.__log.warn("Failed to get common services. This might be okay if no common service has been defined.")

    def _add_endpoints(self, service, endpoints):
        with self.__rLock:
            if service in self.__serviceMap:
                del self.__serviceMap[service]
            self.__serviceMap[service] = []
            for endpoint in endpoints:
                self.__serviceMap[service].append(endpoint)

    @staticmethod
    def __get_thrift_connection_key(service_name, client_class):
        return service_name + "|" + str(client_class)

    def __get_endpoints(self, service_name, retry=True):
        with self.__rLock:
            if service_name in self.__serviceMap:
                return self.__serviceMap[service_name]
        if retry:
            self.__refresh_end_points()
            self.__refresh_common_endpoints()
            return self.__get_endpoints(service_name, retry=False)
        return None

    def get_client(self, app_name=None, service_name=None, clazz=None):

        if not service_name:
            raise ValueError("'service_name' does not have a valid value (%s)." % service_name)

        if not clazz:
            raise ValueError("'clazz' does not have a valid value (%s)." % clazz)

        try:
            key = self.__get_thrift_connection_key(service_name, clazz)
            with self.__rLock:

                if app_name:
                    service = self.__applicationConfiguration.getApplicationServiceName(app_name, service_name)
                    if service not in self.__serviceMap:
                        endpoints = self.ezd_client.get_endpoints(app_name, service_name)
                        self._add_endpoints(service, endpoints)

                # get client from client pool, or initialize client
                if key in self.__clientMap:
                    client = self.__clientMap[key]
                else:
                    endpoints = self.__get_endpoints(service_name)
                    if endpoints is None:
                        return None

                    pool_size = self.__thriftConfiguration.getMaxIdleClients()
                    if self.__thriftConfiguration.useSSL():
                        sc = self.__securityConfiguration
                        ca_certs = sc.getTrustedSslCerts()
                        key_file = sc.getPrivateKey()
                        cert = sc.getSslCertificate()
                        client = PoolingThriftClient(endpoints, clazz, pool_size=pool_size,
                                                     use_ssl=True, ca_certs=ca_certs, cert=cert, key=key_file)
                    else:
                        client = PoolingThriftClient(endpoints, clazz, pool_size=pool_size)

                    self.__clientMap[key] = client
                return client

        except Exception, e:
            raise TException(str(e))

    def __is_common_service(self, service_name):

        if service_name in self.__common_services:
            return True

        if self.ezd_client.is_service_common(service_name):
            self.__common_services.append(service_name)
            return True
        return False

    def close(self):
        try:
            with self.__rLock:
                for key in self.__clientMap:
                    client = self.__clientMap[key]
                    client.close()
                self.__clientMap.clear()
                self.__serviceMap.clear()
        except Exception as e:
            raise TException(str(e))
