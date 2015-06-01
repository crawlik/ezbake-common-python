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

import os
import functools
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
import base64

from ezbake.configuration.constants import constants
from .properties import EzProperties
from .security.CryptoImplementations import SharedSecretTextCryptoImplementation, NoOpTextCryptoImplementation


##
class BaseConfiguration(object):
    def __init__(self, ezprops, namespace=''):
        if not isinstance(ezprops, EzProperties):
            raise TypeError('Invalid object type for ezprops. Got %s' % type(ezprops).__name__)
        if not isinstance(namespace, str):
            raise TypeError('namespace must be of type - str')
        self.__namespace = namespace
        self._ezprops = ezprops

    def _parseKey(self, key):
        return key if not self.__namespace else '%s.%s' % (self.__namespace, key)


##
class EncryptedPropertiesConfiguration(object):
    def __init__(self, ezprops):
        if not isinstance(ezprops, EzProperties):
            raise TypeError('Invalid object type for ezprops. Got %s' % type(ezprops).__name__)
        if ezprops.getTextCryptoImplementer() is None:
            ezprops.setTextCryptoImplementer(SystemConfiguration(ezprops).getTextCryptoImplementer())


##
class AccumuloConfiguration(BaseConfiguration, EncryptedPropertiesConfiguration):
    def __init__(self, ezprops, namespace=''):
        BaseConfiguration.__init__(self, ezprops, namespace)
        EncryptedPropertiesConfiguration.__init__(self, ezprops)

    def getAccumuloInstance(self):
        return self._ezprops.getProperty(self._parseKey(constants.ACCUMULO_INSTANCE_NAME))

    def getZookeepers(self):
        return self._ezprops.getProperty(self._parseKey(constants.ACCUMULO_ZOOKEEPERS))

    def useMock(self):
        return self._ezprops.getBoolean(self._parseKey(constants.ACCUMULO_USE_MOCK), False)

    def getUsername(self):
        return self._ezprops.getProperty(self._parseKey(constants.ACCUMULO_USERNAME))

    def getPassword(self):
        return self._ezprops.getProperty(self._parseKey(constants.ACCUMULO_PASSWORD))

    def getProxyHost(self):
        return self._ezprops.getProperty(self._parseKey(constants.ACCUMULO_PROXY_HOST))

    def getProxyPort(self):
        return self._ezprops.getInteger(self._parseKey(constants.ACCUMULO_PROXY_PORT), 42424)


##
class ApplicationConfiguration(BaseConfiguration):
    __APPLICATION_SERVICE_SEPERATOR = '_'

    def __init__(self, ezprops, namespace=''):
        BaseConfiguration.__init__(self, ezprops, namespace)

    def getApplicationName(self):
        return self._ezprops.getProperty(self._parseKey(constants.EZBAKE_APPLICATION_NAME))

    def getApplicationVersion(self):
        return self._ezprops.getProperty(self._parseKey(constants.EZBAKE_APPLICATION_VERSION))

    def getServiceName(self):
        return self._ezprops.getProperty(self._parseKey(constants.EZBAKE_SERVICE_NAME))

    def getSecurityID(self):
        return self._ezprops.getProperty(self._parseKey(constants.EZBAKE_SECURITY_ID))

    def getCertificatesDir(self):
        return self._ezprops.getPath(self._parseKey(constants.EZBAKE_CERTIFICATES_DIRECTORY), '')

    def getApplicationServiceName(self, applicationName=None, serviceName=None):
        appName = applicationName if applicationName is not None else self.getApplicationName()
        serName = serviceName if serviceName is not None else self.getServiceName()
        return appName + \
            ApplicationConfiguration.__APPLICATION_SERVICE_SEPERATOR + \
            serName


##
class ElasticsearchConfiguration(BaseConfiguration):
    ELASTICSEARCH_DEFAULT_PORT = 9200
    ELASTICSEARCH_DEFAULT_THRIFT_PORT = 9500

    def __init__(self, ezprops, namespace=''):
        BaseConfiguration.__init__(self, ezprops, namespace)

    def getElasticsearchHost(self):
        return self._ezprops.getProperty(self._parseKey(constants.ELASTICSEARCH_HOST))

    def getElasticsearchPort(self):
        return self._ezprops \
                   .getInteger(self._parseKey(constants.ELASTICSEARCH_PORT),
                           ElasticsearchConfiguration.ELASTICSEARCH_DEFAULT_PORT)

    def getElasticsearchThriftPort(self):
        return self._ezprops \
                   .getInteger(self._parseKey(constants.ELASTICSEARCH_THRIFT_PORT),
                           ElasticsearchConfiguration.ELASTICSEARCH_DEFAULT_THRIFT_PORT)

    def getElasticsearchClusterName(self):
        return self._ezprops.getProperty(self._parseKey(constants.ELASTICSEARCH_CLUSTER_NAME))

    def getForceRefresh(self):
        return self._ezprops \
                   .getBoolean(self._parseKey(constants.ELASTICSEARCH_FORCE_REFRESH_ON_PUT),
                               False)


##
class FlumeConfiguration(BaseConfiguration):
    DEFAULT_BATCH_SIZE = 100
    DEFAULT_MAX_EVENTS = 10000
    DEFAULT_MAX_ATTEMPTS = 2
    DEFAULT_CONNECT_ATTEMPTS = 10

    DEFAULT_RUN_INTERVAL = 1000
    DEFAULT_SLEEP_INTERVAL = 3000
    DEFAULT_CONNECT_TIMEOUT = 20000
    DEFAULT_REQUEST_TIMEOUT = 20000
    DEFAULT_MAX_BACKOFF = 0

    DEFAULT_HEADERS = ''
    DEFAULT_AGENT_TYPE = 'SINGLE'
    DEFAULT_HOSTS = 'logAgent00 logAgent01'
    DEFAULT_HOST_SELECTOR = 'ROUND_ROBIN'

    DEFAULT_BACK_OFF = False

    def __init__(self, ezprops, namespace=''):
        BaseConfiguration.__init__(self, ezprops, namespace)
        self.__hostProperties = EzProperties()
        self.__properties = EzProperties()
        if cryptoImplementer is not None:
            self.__hostProperties.setTextCryptoImplementer(cryptoImplementer)
            self.__properties.setTextCryptoImplementer(cryptoImplementer)

    def getBatchSize(self):
        return self._ezprops.getInteger(self._parseKey(constants.FLUME_BATCH_SIZE),
                                        FlumeConfiguration.DEFAULT_BATCH_SIZE)
    def getMaxAttempts(self):
        return self._ezprops.getInteger(self._parseKey(constants.FLUME_MAX_ATTEMPTS),
                                        FlumeConfiguration.DEFAULT_MAX_ATTEMPTS)
    def getConnectAttempts(self):
        return self._ezprops.getInteger(self._parseKey(constants.FLUME_CONNECT_ATTEMPTS),
                                        FlumeConfiguration.DEFAULT_CONNECT_ATTEMPTS)

    def getRunInterval(self):
        return self._ezprops.getLong(self._parseKey(constants.FLUME_RUN_INTERVAL),
                                     FlumeConfiguration.DEFAULT_RUN_INTERVAL)

    def getSleepInterval(self):
        return self._ezprops.getLong(self._parseKey(constants.FLUME_SLEEP_INTERVAL),
                                     FlumeConfiguration.DEFAULT_SLEEP_INTERVAL)

    def getConnectTimeout(self):
        return self._ezprops.getLong(self._parseKey(constants.FLUME_CONNECT_TIMEOUT),
                                     FlumeConfiguration.DEFAULT_CONNECT_TIMEOUT)

    def getRequestTimeout(self):
        return self._ezprops.getLong(self._parseKey(constants.FLUME_REQUEST_TIMEOUT),
                                     FlumeConfiguration.DEFAULT_REQUEST_TIMEOUT)

    def getMaxBackoff(self):
        return self._ezprops.getLong(self._parseKey(constants.FLUME_MAX_BACKOFF),
                                     FlumeConfiguration.DEFAULT_MAX_BACKOFF)

    def getMaxEvents(self):
        return self._ezprops.getLong(self._parseKey(constants.FLUME_MAX_EVENTS),
                                     FlumeConfiguration.DEFAULT_MAX_EVENTS)

    def getHeaders(self):
        return self._ezprops.getString(self._parseKey(constants.FLUME_HEADERS),
                                       FlumeConfiguration.DEFAULT_HEADERS)

    def getAgentType(self):
        return self._ezprops.getString(self._parseKey(constants.FLUME_AGENT_TYPE),
                                       FlumeConfiguration.DEFAULT_AGENT_TYPE)

    def getHosts(self):
        return self._ezprops.getString(self._parseKey(constants.FLUME_HOSTS),
                                       FlumeConfiguration.DEFAULT_HOSTS)

    def getHostSelector(self):
        return self._ezprops.getString(self._parseKey(constants.FLUME_HOST_SELECTOR),
                                       FlumeConfiguration.DEFAULT_HOST_SELECTOR)

    def getBackoff(self):
        return self._ezprops.getBoolean(self._parseKey(constants.FLUME_BACK_OFF),
                                        FlumeConfiguration.DEFAULT_BACK_OFF)

    def getHostProperties(self):
        return self.__hostProperties

    def setHostProperties(self, sHosts):
        if not isinstance(sHosts, str):
            raise TypeError('expecting a string of hosts')
        self.__hostProperties.update((host, self._ezprops.getProperty(self._parseKey('hosts.' + host), '')) for host in sHosts.split())

    def getProperties(self):
        self.__properties[constants.FLUME_BATCH_SIZE] = self.getBatchSize()
        self.__properties[constants.FLUME_MAX_EVENTS] = self.getMaxEvents()
        self.__properties[constants.FLUME_MAX_ATTEMPTS] = self.getMaxAttempts()
        self.__properties[constants.FLUME_CONNECT_ATTEMPTS] = self.getConnectAttempts()

        self.__properties[constants.FLUME_RUN_INTERVAL] = self.getRunInterval()
        self.__properties[constants.FLUME_SLEEP_INTERVAL] = self.getSleepInterval()
        self.__properties[constants.FLUME_CONNECT_TIMEOUT] = self.getConnectTimeout()
        self.__properties[constants.FLUME_REQUEST_TIMEOUT] = self.getRequestTimeout()
        self.__properties[constants.FLUME_MAX_BACKOFF] = self.getMaxBackoff()

        self.__properties[constants.FLUME_HEADERS] = self.getHeaders()
        self.__properties[constants.FLUME_AGENT_TYPE] = self.getAgentType()
        self.__properties[constants.FLUME_HOSTS] = self.getHosts()
        self.__properties[constants.FLUME_HOST_SELECTOR] = self.getHostSelector()

        self.__properties[constants.FLUME_BACK_OFF] = self.getBackoff()

        self.setHostProperties(self.getHosts())

        return self.__properties


##
class HDFSConfiguration(BaseConfiguration):
    def __init__(self, ezprops, namespace=''):
        BaseConfiguration.__init__(self, ezprops, namespace)

    def getFileSystemName(self):
        return self._ezprops.getProperty(self._parseKey(constants.HADOOP_FILESYSTEM_NAME))

    def getFileSystemNameWithDefault(self):
        return self._ezprops.getProperty(self._parseKey(constants.HADOOP_FILESYSTEM_NAME),
                                         'hdfs://127.0.0.1:8020')

    def getUseLocal(self):
        return self._ezprops.getBoolean(self._parseKey(constants.HADOOP_FILESYSTEM_USE_LOCAL),
                                        False)

    def getFileSystemImpl(self):
        return self._ezprops.getProperty(self._parseKey(constants.HADOOP_FILESYSTEM_IMPL),
                                         'org.apache.hadoop.hdfs.DistributedFileSystem')


##
class KafkaConfiguration(BaseConfiguration):
    def __init__(self, ezprops, namespace=''):
        BaseConfiguration.__init__(self, ezprops, namespace)

    def getKafkaZookeeper(self):
        return self._ezprops.getProperty(self._parseKey(constants.KAFKA_ZOOKEEPER))

    def getKafkaBrokerList(self):
        return self._ezprops.getProperty(self._parseKey(constants.KAFKA_BROKER_LIST))

    def getKafkaProducerType(self):
        return self._ezprops.getProperty(self._parseKey(constants.KAFKA_PRODUCER_TYPE))

    def getKafkaQueueSize(self):
        return self._ezprops.getProperty(self._parseKey(constants.KAFKA_QUEUE_SIZE))

    def getKafkaQueueTime(self):
        return self._ezprops.getProperty(self._parseKey(constants.KAFKA_QUEUE_TIME))

    def getKafkaZookeeperSessionTimeout(self):
        return self._ezprops.getProperty(self._parseKey(constants.KAFKA_ZOOKEEPER_SESSION_TIMEOUT))


##
class MongoDBConfiguration(BaseConfiguration, EncryptedPropertiesConfiguration):
    def __init__(self, ezprops, namespace=''):
        BaseConfiguration.__init__(self, ezprops, namespace)
        EncryptedPropertiesConfiguration.__init__(self, ezprops)

    def getMongoDBHostName(self):
        return self._ezprops.getProperty(self._parseKey(constants.MONGODB_HOST_NAME))

    def getMongoDBDatabaseName(self):
        return self._ezprops.getProperty(self._parseKey(constants.MONGODB_DB_NAME))

    def getMongoDBUserName(self):
        return self._ezprops.getProperty(self._parseKey(constants.MONGODB_USER_NAME))

    def getMongoDBPassword(self):
        return self._ezprops.getProperty(self._parseKey(constants.MONGODB_PASSWORD))

    def useMongoDBSSL(self):
        return self._ezprops.getBoolean(self._parseKey(constants.MONGODB_USE_SSL),
                                        True)

    def getMongoDBPort(self):
        return self._ezprops.getInteger(self._parseKey(constants.MONGODB_PORT),
                                        27017)

    def getMongoConnectionString(self):
        return 'mongodb://' + self.getMongoDBUserName() + ':' + self.getMongoDBPassword() + '@' + \
               self.getMongoDBHostName() + ':' + str(self.getMongoDBPort()) + '/' + \
               self.getMongoDBDatabaseName() + '?ssl=' + str(self.useMongoDBSSL()).lower()


##
class PostgresConfiguration(BaseConfiguration, EncryptedPropertiesConfiguration):
    def __init__(self, ezprops, namespace=''):
        BaseConfiguration.__init__(self, ezprops, namespace)
        EncryptedPropertiesConfiguration.__init__(self, ezprops)

    def getHost(self):
        return self._ezprops.getProperty(self._parseKey(constants.POSTGRES_HOST))

    def getPort(self):
        return self._ezprops.getInteger(self._parseKey(constants.POSTGRES_PORT), 5432)

    def getUsername(self):
        return self._ezprops.getProperty(self._parseKey(constants.POSTGRES_USERNAME))

    def getPassword(self):
        return self._ezprops.getProperty(self._parseKey(constants.POSTGRES_PASSWORD))

    def getDatabase(self):
        return self._ezprops.getProperty(self._parseKey(constants.POSTGRES_DB))

    def getConnectionUrl(self):
        return "ezbake://" + self.getHost() + ":" + str(self.getPort()) + "/" + self.getDatabase()


##
class RedisConfiguration(BaseConfiguration):
    def __init__(self, ezprops, namespace=''):
        BaseConfiguration.__init__(self, ezprops, namespace)

    def getRedisHost(self):
        return self._ezprops.getProperty(self._parseKey(constants.REDIS_HOST))

    def getRedisPort(self):
        return self._ezprops.getInteger(self._parseKey(constants.REDIS_PORT),
                                        6379)


##
class SecurityConfiguration(BaseConfiguration):
    DEFAULT_SSL_PROTOCOL = 'TLSv1'
    DEFAULT_SSL_CIPHERS = 'DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES256-SHA:RC4-SHA!DSS:!aNULL@STRENGTH'
    DEFAULT_TURSTED_SSL_CERTS = "ezbakeca.crt";
    DEFAULT_SSL_CERT = "application.crt";
    DEFAULT_PRIVATE_KEY = "application.priv";
    DEFAULT_SERVICE_PUBLIC_KEY = "ezbakesecurityservice.pub";


    def __init__(self, ezprops, namespace=''):
        BaseConfiguration.__init__(self, ezprops, namespace)
        appHelper = ApplicationConfiguration(ezprops, namespace)
        self.__securityId = appHelper.getSecurityID()
        self.__certificateDir = appHelper.getCertificatesDir()
        self.__privateKey = None
        self.__publicKey = None

    #EzSecurity Caching accessors
    def getUserCacheTTL(self):
        return self._ezprops.getInteger(self._parseKey(constants.EZBAKE_USER_CACHE_TTL), 43200)

    def getUserCacheSize(self):
        return self._ezprops.getInteger(self._parseKey(constants.EZBAKE_USER_CACHE_SIZE), 1000)

    #EzSecurity Token accessors
    def getRequestsExpiration(self):
        return self._ezprops.getInteger(self._parseKey(constants.EZBAKE_REQUEST_EXPIRATION), 60)

    def getTokenExpiration(self):
        return self._ezprops.getInteger(self._parseKey(constants.EZBAKE_TOKEN_EXPIRATION), 7200)

    #EzSecurity Mock accessors
    def useMockServer(self):
        return self._ezprops.getBoolean(self._parseKey(constants.EZBAKE_SECURITY_SERVICE_MOCK_SERVER), False)

    #EzFrontend Proxy accessors
    def useForwardProxy(self):
        return self._ezprops.getBoolean(self._parseKey(constants.EZBAKE_USE_FORWARD_PROXY), False)

    #SSL accessors
    def getCertificatesDir(self):
        return self.__certificateDir

    def getSecurityId(self):
        return self.__securityId

    def isPeerAuthRequired(self):
        return self._ezprops.getBoolean(self._parseKey(constants.EZBAKE_SSL_PEER_AUTH_REQUIRED),
                                        True)

    def getSslProtocol(self):
        return self._ezprops.getProperty(self._parseKey(constants.EZBAKE_SSL_PROTOCOL_KEY),
                                         SecurityConfiguration.DEFAULT_SSL_PROTOCOL)

    def getSslCiphers(self):
        return self._ezprops.getProperty(self._parseKey(constants.EZBAKE_SSL_CIPHERS_KEY),
                                         SecurityConfiguration.DEFAULT_SSL_CIPHERS)

    def trustedCert(self, serviceName=''):
        return self._ezprops.getProperty(\
                    SecurityConfiguration.parseServiceKey(\
                        self._parseKey(constants.EZBAKE_APPLICATION_TRUSTED_CERT), serviceName),
                                       SecurityConfiguration.DEFAULT_TURSTED_SSL_CERTS)
    def privateKey(self, serviceName=''):
        return self._ezprops.getProperty(\
                    SecurityConfiguration.parseServiceKey(\
                        self._parseKey(constants.EZBAKE_APPLICATION_PRIVATE_KEY_FILE), serviceName),
                                       SecurityConfiguration.DEFAULT_PRIVATE_KEY)

    def certificate(self, serviceName=''):
        return self._ezprops.getProperty(\
                    SecurityConfiguration.parseServiceKey(\
                        self._parseKey(constants.EZBAKE_APPLICATION_CERT_FILE), serviceName),
                                       SecurityConfiguration.DEFAULT_SSL_CERT)

    def servicePublicKey(self, serviceName=''):
        return self._ezprops.getProperty(\
                    SecurityConfiguration.parseServiceKey(\
                        self._parseKey(constants.EZBAKE_APPLICATION_PUBLIC_KEY_FILE), serviceName),
                                       SecurityConfiguration.DEFAULT_SERVICE_PUBLIC_KEY)

    def getPrivateKey(self, serviceName=''):
        return os.path.join(self.__certificateDir, self.privateKey(serviceName))

    def getTrustedSslCerts(self, serviceName=''):
        return os.path.join(self.__certificateDir, self.trustedCert(serviceName))

    def getSslCertificate(self, serviceName=''):
        return os.path.join(self.__certificateDir, self.certificate(serviceName))

    def getServicePublicKey(self, serviceName=''):
        return os.path.join(self.__certificateDir, self.servicePublicKey(serviceName))

    def setPrivateKey(self, serviceName=''):
        with open(self.getPrivateKey(serviceName)) as file:
            self.__privateKey = RSA.importKey(file.read())

    def setPublicKey(self, serviceName=''):
        with open(self.getServicePublicKey(serviceName)) as file:
            self.__publicKey = RSA.importKey(file.read())

    def setKeys(self):
        self.setPrivateKey()
        self.setPublicKey()

    def hasPrivateKeySet(self):
        return True if self.__privateKey is not None else False

    def hasPublicKeySet(self):
        return True if self.__publicKey is not None else False

    def hasKeysSet(self):
        return self.hasPrivateKeySet() & self.hasPublicKeySet()

    def sign(self, serializedData):
        if not self.hasPrivateKeySet():
            raise RuntimeError('Cannot sign data. Private key has not been set. Did you call setPrivateKey/setKeys?')
        try:
            signer = PKCS1_v1_5.new(self.__privateKey)
            digest = SHA256.new(serializedData)
            return base64.b64encode(signer.sign(digest))
        except Exception as ex:
            raise RuntimeError('Error in signing data: %s' % str(ex))

    def verify(self, serializedData, signature):
        if not self.hasPublicKeySet():
            raise RuntimeError('Cannot verify data. Public key has not been set. Did you call setPublicKey/setKeys?')
        try:
            signer = PKCS1_v1_5.new(self.__publicKey)
            digest = SHA256.new(serializedData)
            return signer.verify(digest, base64.b64decode(signature))
        except Exception as ex:
            raise RuntimeError('Error in verifying data: %s' % str(ex))

    @staticmethod
    def parseServiceKey(key, serviceName=''):
        if serviceName.strip():
            return key + '.' + serviceName
        return key


##
class SystemConfiguration(BaseConfiguration):
    def __init__(self, ezprops):
        BaseConfiguration.__init__(self, ezprops)
        self.__appConfig = ApplicationConfiguration(ezprops)

    def getLogDirectory(self):
        logDir = self._ezprops.getProperty(constants.EZBAKE_LOG_DIRECTORY)
        return logDir if logDir is not None else '/tmp'

    def shouldLogToStdOut(self):
        return self._ezprops.getBoolean(constants.EZBAKE_LOG_TO_STDOUT, False)

    def isAdminApplicationDeployment(self):
        return self._ezprops.getBoolean(constants.EZBAKE_ADMIN_APPLICATION_DEPLOYMENT,
                                        True)

    def getTextCryptoImplementer(self):
        sharedSecretEnvKey = self._ezprops.get(constants.EZBAKE_SHARED_SECRET_ENVIRONMENT_VARIABLE)
        if sharedSecretEnvKey is not None:
            secret = os.getenv(sharedSecretEnvKey)
            if secret is not None:
                return SharedSecretTextCryptoImplementation(secret)
        return NoOpTextCryptoImplementation()

    def getLogFilePath(self, applicationName, serviceName):
        if not isinstance(serviceName, str):
            raise TypeError('serviceName should be a non-empty string')

        path = self.getLogDirectory()
        if applicationName is not None:
            if not isinstance(applicationName, str):
                raise TypeError('applicationName should be a string')
            path = os.path.join(path, applicationName)
            fileName = self.__appConfig.getApplicationServiceName(applicationName,
                                                                  serviceName) + '.log'
        else:
            path = os.path.join(path, serviceName)
            fileName = serviceName + '.log'

        return os.path.join(path, fileName)


##
# Removed functools.total_ordering decorator to support 2.6
#@functools.total_ordering
class ThriftServerMode(object):
    VALUES = ['Simple', 'HsHa', 'ThreadedPool']

    def __init__(self, value, isBlocking):
        self.__value = value
        self.__isBlocking = isBlocking

    def __str__(self):
        return self.__value

    def __eq__(self, rhs):
        return self.__dict__ == rhs.__dict__

    def __ne__(self, rhs):
        return self.__dict__ != rhs.__dict__

    def __lt__(self, rhs):
        return ThriftServerMode.VALUES.index(self.__value) < ThriftServerMode.VALUES.index(rhs.__value)

    def isBlocking(self):
        return self.__isBlocking

    @staticmethod
    def valueOf(value):
        if not isinstance(value, str):
            raise TypeError('value must be of type str')
        if value not in ThriftServerMode.VALUES:
            raise ValueError('%s value is not in the set %s' % (value, ThriftServerMode.VALUES))

        if value == ThriftServerMode.VALUES[0]: return ThriftServerMode(ThriftServerMode.VALUES[0], True)
        elif value == ThriftServerMode.VALUES[1]: return ThriftServerMode(ThriftServerMode.VALUES[1], False)
        elif value == ThriftServerMode.VALUES[2]: return ThriftServerMode(ThriftServerMode.VALUES[2], True)

class ThriftConfiguration(BaseConfiguration):
    SIMPLE = ThriftServerMode.valueOf(ThriftServerMode.VALUES[0])
    HSHA = ThriftServerMode.valueOf(ThriftServerMode.VALUES[1])
    THREADED_POOL = ThriftServerMode.valueOf(ThriftServerMode.VALUES[2])

    def __init__(self, ezprops):
        BaseConfiguration.__init__(self, ezprops)

    def useSSL(self):
        return self._ezprops.getBoolean(constants.THRIFT_USE_SSL, True)

    def getServerMode(self):
        mode = self._ezprops.getProperty(constants.THRIFT_SERVER_MODE,
                                         str(ThriftConfiguration.SIMPLE))
        return ThriftServerMode.valueOf(mode)

    def getMaxIdleClients(self):
        return self._ezprops.getInteger(constants.THRIFT_MAX_IDLE_CLIENTS, 10)

    def getMillisBetweenClientEvictionChecks(self):
        return self._ezprops.getLong(constants.THRIFT_MILLIS_BETWEEN_CLIENT_EVICTION_CHECKS,
                                     30 * 1000)

    def getMillisIdleBeforeEviction(self):
        return self._ezprops.getLong(constants.THRIFT_MILLIS_IDLE_BEFORE_EVICTION,
                                     2 * 60 * 1000)

    def getMaxPoolClients(self):
        return self._ezprops.getInteger(constants.THRIFT_MAX_POOL_CLIENTS, 10)

    def getTestOnBorrow(self):
        return self._ezprops.getBoolean(constants.THRIFT_TEST_ON_BORROW, False)

    def getTestWhileIdle(self):
        return self._ezprops.getBoolean(constants.THRIFT_TEST_WHILE_IDLE, True)


##
class WebApplicationConfiguration(BaseConfiguration):
    def __init__(self, ezprops, namespace=''):
        BaseConfiguration.__init__(self, ezprops, namespace)

    def getExternalFacingDomain(self):
        return self._ezprops.getProperty(constants.EZBAKE_WEB_APPLICATION_EXTERNAL_DOMAIN)

    def getMetricsRESTEndpoint(self):
        return self._ezprops.getProperty(constants.EZBAKE_WEB_APPLICATION_METRICS_ENDPOINT)

    def getMetricsSiteId(self):
        return self._ezprops.getProperty(constants.EZBAKE_WEB_APPLICATION_METRICS_SITEID)


##
class ZookeeperConfiguration(BaseConfiguration):
    def __init__(self, ezprops):
        BaseConfiguration.__init__(self, ezprops)

    def getZookeeperConnectionString(self):
        return self._ezprops.getProperty(constants.ZOOKEEPER_CONNECTION_STRING)


