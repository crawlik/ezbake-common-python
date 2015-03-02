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

# -*- coding: utf-8 -*-
"""
Created on Wed Nov 13 13:11:47 2013

@author: jhastings
"""
import logging
import os

from ezbake.security.thriftapi import EzSecurity
from ezbake.security.thriftapi.EzSecurity import Client
from ezbake.security.thriftapi.constants import SECURITY_SERVICE_NAME


from ezbake.base.thriftapi.ttypes import (TokenRequest, TokenType, ProxyUserToken, ProxyPrincipal, X509Info)
from ezbake.configuration import helpers as ezc_helpers
from ezbake.thrift.utils.clientpool import ThriftClientPool
from ezbake.discovery import ServiceDiscoveryClient

from . import util

USE_MOCK_KEY = "ezbake.security.client.use.mock"
MOCK_USER_DN = "ezbake.security.client.mock.user.dn"
MOCK_TARGET_ID_KEY = "ezbake.security.client.mock.target.id"
MOCK_SERVER_KEY_PRIVATE = 'ezbake.ssl.privateservicekey.file'

HTTP_HEADER_USER_INFO = 'ezb_verified_user_info'
HTTP_HEADER_SIGNATURE = 'ezb_verified_signature'

DEFAULT_EVICT_CYCLE = 60 * 1000


class EzSecurityClient(object):
    """
    Wrapper around the Ezbake Security thrift client

    Handles the PKI stuff surrounding request/response data in ezbake security
    """

    token_cache = None

    def __init__(self, ez_props, client_pool=None, cache_evict_cycle=DEFAULT_EVICT_CYCLE,
                 log=logging.getLogger(__name__), handler=None):
        """
        """
        if EzSecurityClient.token_cache is None:
            EzSecurityClient.token_cache = TokenCache(cache_evict_cycle)

        self.ez_props = ez_props
        self.securityConfig = ezc_helpers.SecurityConfiguration(ez_props)
        self.appConfig = ezc_helpers.ApplicationConfiguration(ez_props)
        self.zk_con_str = ezc_helpers.ZookeeperConfiguration(ez_props).getZookeeperConnectionString()

        if client_pool is None:
            self.client_pool = ThriftClientPool(ez_props)
            self.__local_pool = True
        else:
            self.client_pool = client_pool
            self.__local_pool = False

        self.client = self.client_pool.get_client(SECURITY_SERVICE_NAME, EzSecurity.Client)

        self.privateKey = None
        self.servicePublic = None
        self.servicePrivate = None

        self.log = log
        self.handler = handler

        self.mock = ez_props.getBoolean(USE_MOCK_KEY, False)
        self.log.info("%s has mock config set to %s",
                      self.__class__.__name__, self.mock)

    @staticmethod
    def _read_file(filename):
        """
        Helper to read public/private keys where necessary
        @return the files bytes
        """
        with open(filename, 'r') as f:
            b = f.read()
        return b

    @staticmethod
    def principal_from_request(headers):
        """
        Builds a ProxyPrincipal object
        (ProxyPrincipal(proxyUser:string, signature:string)) from the
        "EZB_VERIFIED_USER_INFO" and "EZB_VERIFIED_SIGNATURE" headers.

        :param headers: dict
        :return:
        """
        dn = headers.get(HTTP_HEADER_USER_INFO)
        signature = headers.get(HTTP_HEADER_SIGNATURE)

        if dn and signature not in (None, False):
            proxy_principal = ProxyPrincipal(dn, signature)
            return proxy_principal

    @staticmethod
    def _cache_key(target_app, subject):
        return "{};{}".format(target_app, subject)

    @staticmethod
    def _get_cache_key(token_type, subject, exclude_auths=None, request_chain=None, target_security_id=None):
        li = []
        chk_append = lambda l, a: l.append(a) if a is not None else None
        chk_append(li, str(token_type))
        chk_append(li, subject)
        ea_str = None if exclude_auths is None else ';'.join(sorted(exclude_auths))
        chk_append(li, ea_str)
        rc_str = None if request_chain is None else ';'.join(request_chain)
        chk_append(li, rc_str)
        chk_append(li, target_security_id)
        return '|'.join(li)

    def get_client(self):
        """
        Returns an EzSecurity.Client object that users can use to call the
        EzSecurity service directly.
        """
        self.client_pool.get_client(SECURITY_SERVICE_NAME, Client)

    def close_client_pool(self):
        if self.__local_pool:
            self.client_pool.close()

    def _ensure_keys(self):
        if self.privateKey is None:
            self.privateKey = self._read_file(
                self.securityConfig.getPrivateKey())

        if self.servicePublic is None:
            self.servicePublic = self._read_file(
                self.securityConfig.getServicePublicKey())

        # attempt to get the server's private key if we're in the mock-mode
        if self.mock and not self.servicePrivate:
            private_key_path = self.ez_props.getProperty(
                MOCK_SERVER_KEY_PRIVATE)
            private_key_exists = \
                os.path.exists(private_key_path) if private_key_path else False
            if private_key_path and private_key_exists:
                self.servicePrivate = self._read_file(private_key_path)

    def _sign(self, data):

        self._ensure_keys()
        return util.ssl_sign(data, self.privateKey)

    def _mock_service_sign(self, data):
        """
        Looks up the service's private key if the client is in mock-mode, and
        and signs the data with the server's private key.

        WARNING: DO NOT USE THIS METHOD FOR CODE THAT WILL BE USED IN PROD.

        :param data:
        :return:
        """
        if self.mock:
            self._ensure_keys()
            if self.servicePrivate is not None:
                return util.ssl_sign(data, self.servicePrivate)
            else:
                return ""

        raise ValueError("_mock_service_sign can only be called in mock-mode.")

    def ping(self):
        """
        Ping the security service
        @return true if the service is healthy
        """
        ret = self.client.ping()
        return ret

    def _user_dn(self, dn):
        """
        Request a signed DN from the security service. Note this will most
        likely fail, since it only signs DNs for the EFE
        @param dn: the user's X509 subject
        @return an EzSecurityPrincipal with a valid signature
        """
        headers = {
            HTTP_HEADER_USER_INFO: dn,
            HTTP_HEADER_SIGNATURE: ""
        }
        request, signature = self.build_request(headers)
        dn = self.client.requestUserDN(request, signature)
        return dn

    def fetch_app_token(self, targetApp=None, excludedAuths=None, skipCache=False):
        """
        Request a token containing application info, optionally with a target
        securityId in the token. If the targetApp is specified, you will be
        able to send this token to another application, and it will validate on
        the other end. You should set txApp to
        ApplicationConfiguration(ez_props).getSecurityID() if you are sending
        this to another thrift service within your application
        @param targetApp: optionally, request security service to include a
        targetSecurityId in the token
        @return the EzSecurityToken
        """

        app = self.appConfig.getApplicationName()

        headers = {
            HTTP_HEADER_USER_INFO: app,
            HTTP_HEADER_SIGNATURE: ''
        }

        if targetApp is None:
            targetApp = self.appConfig.getSecurityID()

        # look in the cache
        cache_key = self._get_cache_key(TokenType.APP, headers.get(HTTP_HEADER_USER_INFO), excludedAuths,
                                        target_security_id=targetApp)
        if not skipCache:
            token = self.__get_from_cache(cache_key)
            if token:
                return token

        request, signature = self.build_request(headers, targetApp, token_type=TokenType.APP,
                                                exclude_authorizations=excludedAuths)
        return self._request_token_and_store(request, signature, "app", app, cache_key)

    def fetch_user_token(self, headers, target_app=None, skipCache=False):
        """
        Request a token with user info. Includes a targetSecurityId
        in the token if the txApp is passed. If targetSecurityId is set in the
        token, you will be able to pass this token to other thrift services.
        You should set txApp to
        ApplicationConfiguration(ez_props).getSecurityID() if you are sending
        this to another thrift service within your application,
        @param target_app: optionally, request security service to include a
        targetSecurityId in the token
        @return: the EzSecurityToken
        """
        dn = headers.get(HTTP_HEADER_USER_INFO)

        if target_app is None:
            target_app = self.appConfig.getSecurityID()
        if self.mock and dn is None:
            dn = self.ez_props.get(MOCK_USER_DN)
            if dn is None:
                raise RuntimeError("{0} is in mock mode, but {1} is None".
                                   format(self.__class__, MOCK_USER_DN))

        # look in the cache (and return immediately if in cache)
        cache_key = self._get_cache_key(TokenType.USER, dn, target_security_id=target_app)
        if not skipCache:
            token = self.__get_from_cache(cache_key)
            if token:
                return token

        # get token (since it wasn't found in the cache)
        request, signature = self.build_request(headers, target_app)
        return self._request_token_and_store(request, signature, "user", dn, cache_key)

    def fetch_derived_token(self, ezSecurityToken, targetApp,
                            excludedAuths=None, skipCache=False):
        """
        Used when an application receives an EzSecurityToken as part of it's
        API but needs to call another service that itself takes an
        EzSecurityToken.

        :param ezSecurityToken:
        :param targetApp:
        :param excludedAuths:
        :return:
        """

        # get the security id for target app (depending on if its a common
        # service or an application)
        dc = ServiceDiscoveryClient(self.zk_con_str)
        targetSecurityId = dc.get_security_id(targetApp)
        token_request = TokenRequest(
            self.appConfig.getSecurityID(),
            util.current_time_millis()
        )
        token_request.tokenPrincipal = ezSecurityToken
        token_request.targetSecurityId = targetSecurityId
        token_request.excludeAuthorizations = excludedAuths

        # look in the cache (and return immediately if in cache)
        dn = ezSecurityToken.tokenPrincipal.principal
        request_chain = ezSecurityToken.tokenPrincipal.requestChain
        cache_key = self._get_cache_key(ezSecurityToken.type, dn, excludedAuths, request_chain, targetSecurityId)
        if not skipCache:
            token = self.__get_from_cache(cache_key)
            if token:
                return token

        # get token (since it wasn't found in the cache)
        headers = {
            HTTP_HEADER_USER_INFO: dn,
            HTTP_HEADER_SIGNATURE: self._sign(dn)
        }
        request, signature = self.build_request(headers, targetApp, exclude_authorizations=excludedAuths)
        return self._request_token_and_store(request, signature, "derived", dn, cache_key)

    def _request_token_and_store(self, request, signature, type_info, subject, cache_key):

        self.log.debug("Requesting %s token for %s from EzSecurity", type_info, subject)
        token = self.client.requestToken(request, signature)
        self.log.debug("Received %s token for %s from EzSecurity", type_info, subject)

        # validate the token we received if we're not mocking (i.e.: in dev)
        if not self.mock:
            if not self._validate_token(token):
                self.log.error("Invalid token received from EzSecurity")
                token = None

        if token is not None:
            self.log.info("Storing %s token %s into cache", type_info, subject)
            expires = token.validity.notAfter
            self.token_cache[cache_key] = (expires, token)

        return token

    def __get_from_cache(self, cache_key):
        """
        Shortcut for retrieving contents from cache.
        :param cache_key:
        :return: Contents of cache if found
        """
        try:
            token = self.token_cache[cache_key]
            if self._validate_token(token):
                self.log.info("Using token from cache")
                return token
            else:
                self.log.info("Token in cache was invalid. getting new")
        except KeyError:
            # it's not in the cache, continue
            pass

        return None

    def _validate_token(self, token):
        """
        Internal method for verifying tokens received from the security service
        @param token: the received EzSecurityToken
        @return: true if the token is valid
        """
        self._ensure_keys()
        return util.verify(token, self.servicePublic,
                           self.appConfig.getSecurityID(), None)

    def validate_received_token(self, token):
        """
        Validate a token that was received in a thrift request. This must be
        called whenever your application receives an EzSecurityToken from an
        unknown source (even if you think you know where it came from)
        @param token: the received EzSecurityToken
        @return: true if the token is valid
        """
        if self.mock:
            return True
        self._ensure_keys()
        return util.verify(token, self.servicePublic, None,
                           self.appConfig.getSecurityID())

    def validate_signed_dn(self, dn, signature):
        """
        Validate a DN/Signature pair that is expected to have been signed by
        the security service
        @param dn: the dn
        @param signature: the security service signature
        @return: true if the DN validates
        """
        self._ensure_keys()
        return util.verify_signed_dn(dn, signature, self.servicePublic)

    def build_request(self, headers, target_app=None, token_type=TokenType.USER, exclude_authorizations=None):
        """
        Build a TokenRequest for the given information.
        @param target_app: the optional targetSecurityId
        @return: A TokenRequest for the request
        """
        token = TokenRequest(securityId=self.appConfig.getSecurityID(),
                             targetSecurityId=target_app,
                             timestamp=util.current_time_millis(),
                             type=token_type,
                             excludeAuthorizations=exclude_authorizations)
        token.targetSecurityId = target_app

        if token_type == TokenType.USER:
            token.proxyPrincipal = self.principal_from_request(headers)

        # generate signature
        if not self.mock:
            signature = self._sign(util.serialize_token_request(token))
        else:
            signature = ""

        return token, signature

    def validate_current_request(self, headers):
        """
        Verifies that the dn provided is valid (based on signature) and
        :return: True if the request is valid, False if it is invalid invalid.
        """

        # if we're mocking, return True
        if self.mock and not self.servicePrivate:
            return True

        now = util.current_time_millis()
        try:
            dn = headers[HTTP_HEADER_USER_INFO]
            sig = headers[HTTP_HEADER_SIGNATURE]
            self._ensure_keys()
            pubkey = self.servicePublic

            # verify the user_info header with the signature
            verified = util.verify_proxy_token_signature(dn, sig, pubkey)
            if not verified:
                return False

            # verify that the  ProxyUserToken has not expired
            json_dict = util.deserialize_from_json(dn)

            # populate X509
            x509 = X509Info()
            x509.__dict__.update(json_dict['x509'])

            # populate ProxyUserToken
            proxy_user_token = ProxyUserToken()
            proxy_user_token.__dict__.update(json_dict)
            proxy_user_token.x509 = x509

            if proxy_user_token.notAfter < now:
                return False

            return True
        except KeyError:
            self.log.exception("Unable to validate current request.")
            return False


from threading import RLock, Thread, Condition
import time
sleep_millis = lambda t: time.sleep(t * 0.001)


class TokenCache(dict):

    _instance = None
    _initialized = False
    _rlock = RLock()

    def __new__(cls, *args, **kwargs):
        """
        Create the cache as a singleton.

        :param cls:
        :param args:
        :param kwargs:
        :return:
        """
        if cls._instance is None:
            with cls._rlock:
                if cls._instance is None:
                    cls._instance = super(TokenCache, cls).__new__(cls, *args)

        return cls._instance

    def __init__(self, evict_cycle_millis=DEFAULT_EVICT_CYCLE, *args, **kwargs):
        """
        Initializes ExpiringCache
        :param ttl_secs:
        :return:
        """
        self.rlock = self.__class__._rlock
        with self.rlock:

            self.evict_cycle_millis = evict_cycle_millis
            if self.__class__._initialized:
                with self.wait_condition:
                    self.wait_condition.notify_all()
                    # this end the current wait on evict daemon, evict dict, and start wait on new cycle.
                return

            self.wait_condition = Condition()

            super(TokenCache, self).__init__(*args, **kwargs)
            self._expires = getattr(self, '_expires', {})

            thread = Thread(target=self._evict_daemon)
            thread.setDaemon(True)
            thread.start()

            self.__class__._initialized = True

    def _evict_daemon(self):
        while True:
            with self.wait_condition:                                               # interruptable wait
                self.wait_condition.wait(self.evict_cycle_millis * 0.001)

            k_list = []
            for key, expire in self._expires.iteritems():
                if expire < util.current_time_millis():
                    k_list.append(key)

            with self.rlock:
                for key in k_list:
                    del self._expires[key]
                    super(TokenCache, self).__delitem__(key)

    def __setitem__(self, key, (expire, value)):
        """
        Set the value for the given key in the cache. Sets the key with the
        ttl.

        :param key:
        :param value:
        :return:
        """
        with self.rlock:

            self._expires[key] = expire
            super(TokenCache, self).__setitem__(key, value)

    def __getitem__(self, key):
        """
        Get the value for the key in the cache.

        :param key:
        :return:
        """
        self.prune(key)
        return super(TokenCache, self).__getitem__(key)

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

        return super(TokenCache, self).__contains__(k)

    def __delitem__(self, key):
        """
        Deletes the key from the dictionary.

        :param key:
        :return:
        """
        with self.rlock:
            del self._expires[key]
            super(TokenCache, self).__delitem__(key)

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
            if expires_ts < util.current_time_millis():
                del self[key]


    def clear(self):
        """
        Clears the dictionary
        :return:
        """
        with self.rlock:
            for k in self.keys():
                del self[k]
