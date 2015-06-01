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
    similar test as test_client.py but with a golbal client_pool.
"""

import nose.tools as nt
import time
import thrift.TSerialization as TSer


from ezbake.base.thriftapi.ttypes import (TokenRequest, EzSecurityToken)
from ezbake.security.thriftapi import EzSecurity
from ezbake.configuration.EzConfiguration import EzConfiguration
from ezbake.thrift.utils.ezthrifttest import EzThriftServerTestHarness

from ezbake.security.client import (EzSecurityClient, TokenCache, HTTP_HEADER_USER_INFO, HTTP_HEADER_SIGNATURE)
import ezbake.security.client

from .thrift_handler import EzSecurityHandler


from ezbake.thrift.utils.clientpool import ThriftClientPool


class EzSecurityTest(EzThriftServerTestHarness):

    def setUp(self):
        super(EzSecurityTest, self).setUp()

        # load EzConfiguration
        self.ez_props = EzConfiguration().getProperties()
        self.appId = "SecurityClientTest"

        # prior to 2.1-preview, we were passing around ezConfig,
        # but it is better to pass ez_props which inherits from `dict`.
        self.ez_props["zookeeper.connection.string"] = self.hosts
        self.ez_props["thrift.use.ssl"] = "false"
        self.ez_props["ezbake.security.ssl.dir"] = "test/certs/client"
        self.ez_props["ezbake.security.app.id"] = self.appId

        # load private key
        with open("test/certs/server/application.priv", "r") as f:
            rsa = f.read()

        handler = EzSecurityHandler(rsa, token_ttl_millis=500)
        self.add_server(handler.app_name, handler.service_name, host="localhost", port=8449,
                        processor=EzSecurity.Processor(handler), wait=3)

        self.global_client_pool = ThriftClientPool(self.ez_props)

    def tearDown(self):
        self.global_client_pool.close()
        super(EzSecurityTest, self).tearDown()

    def get_client(self):
        return EzSecurityClient(self.ez_props, self.global_client_pool)


class TestEzSecurityClient(EzSecurityTest):
    def test_ping(self):
        client = self.get_client()
        nt.assert_equal(True, client.ping())

    def test_app_info(self):
        client = self.get_client()
        token = client.fetch_app_token('SecurityClientTest')

        nt.assert_is_not_none(token)
        nt.assert_equal(self.appId, token.tokenPrincipal.principal)
        nt.assert_equal(self.appId, token.validity.issuedFor)
        nt.assert_set_equal({'A', 'B', 'C'}, token.authorizations.formalAuthorizations)
        nt.assert_equal("low", token.authorizationLevel)

    def test_app_info_with_target(self):
        client = self.get_client()
        token = client.fetch_app_token('testapp')

        nt.assert_is_not_none(token)
        nt.assert_equal(self.appId, token.tokenPrincipal.principal)
        nt.assert_equal('testapp', token.validity.issuedFor)
        nt.assert_set_equal({'A', 'B', 'C'}, token.authorizations.formalAuthorizations)
        nt.assert_equal("low", token.authorizationLevel)

    def test_user_info(self):
        client = self.get_client()
        subject = "Joe USER"
        headers = {
            HTTP_HEADER_USER_INFO: subject,
            HTTP_HEADER_SIGNATURE: ""
        }
        t = client.fetch_user_token(headers)

        nt.assert_equal(self.appId, t.validity.issuedTo)
        nt.assert_equal(self.appId, t.validity.issuedFor)
        nt.assert_equal(subject, t.tokenPrincipal.principal)
        nt.assert_equal("Joe User", t.tokenPrincipal.name)
        nt.assert_set_equal({'A', 'B', 'C'}, t.authorizations.formalAuthorizations)
        nt.assert_equal("EzBake", t.organization)
        nt.assert_equal("USA", t.citizenship)
        nt.assert_equal("low", t.authorizationLevel)
        nt.assert_dict_equal(dict([
            ('EzBake', ['Core']),
            ('42six', ['Dev', 'Emp']),
            ('Nothing', ['groups', 'group2'])]), t.externalProjectGroups)
        community_membership = t.externalCommunities['EzBake']
        nt.assert_equal("office", community_membership.type)
        nt.assert_equal("EzBake", community_membership.organization)
        nt.assert_true(community_membership.flags['ACIP'])
        nt.assert_list_equal(['topic1', 'topic2'], community_membership.topics)
        nt.assert_list_equal(['region1', 'region2', 'region3'], community_membership.regions)
        nt.assert_list_equal([], community_membership.groups)

    def test_build_request(self):
        client = self.get_client()
        subject = "Joe USER"
        header = {
            HTTP_HEADER_USER_INFO: subject,
            HTTP_HEADER_SIGNATURE: ""
        }
        request, signature = client.build_request(header)
        nt.assert_equal(subject, request.proxyPrincipal.proxyToken)
        nt.assert_equal(self.appId, request.securityId)
        nt.assert_is_instance(request, TokenRequest)

    def test_validate_received_token(self):
        client = self.get_client()
        subject = "Joe USER"
        headers = {
            HTTP_HEADER_USER_INFO: subject,
            HTTP_HEADER_SIGNATURE: ""
        }
        token = client.fetch_user_token(headers, "SecurityClientTest")
        nt.assert_true(client.validate_received_token(token))
        b = TSer.serialize(token)
        token = EzSecurityToken()
        TSer.deserialize(token, b)
        nt.assert_true(client.validate_received_token(token))


class TestEzSecurityClientCache(EzSecurityTest):
    def setUp(self):
        tc = TokenCache()
        tc.clear()                                          # singleton need to be cleared for each test
        super(TestEzSecurityClientCache, self).setUp()

    def tearDown(self):
        super(TestEzSecurityClientCache, self).tearDown()
        EzSecurityClient.token_cache.clear()

    def test_cache_no_target(self):
        client = self.get_client()
        headers = {
            HTTP_HEADER_USER_INFO: "John Snow",
            HTTP_HEADER_SIGNATURE: ""
        }
        t1 = client.fetch_user_token(headers)
        t2 = client.fetch_user_token(headers)
        nt.assert_equal(t1, t2)

    def test_cache_same_target(self):
        client = self.get_client()
        headers = {
            HTTP_HEADER_USER_INFO: "Joffrey Baratheon",
            HTTP_HEADER_SIGNATURE: ""
        }
        t1 = client.fetch_user_token(headers, "SecurityClientTest")
        t2 = client.fetch_user_token(headers, "SecurityClientTest")
        nt.assert_equal(t1, t2)

    def test_cache_diff_target(self):
        client = self.get_client()
        headers = {
            HTTP_HEADER_USER_INFO: "Brienne of Tarth",
            HTTP_HEADER_SIGNATURE: ""
        }
        t1 = client.fetch_user_token(headers, "SecurityClientTest")
        t2 = client.fetch_user_token(headers, "NotSecurityClientTest")
        nt.assert_not_equal(t1, t2)

    def test_cache_expire(self):
        client = self.get_client()
        headers = {
            HTTP_HEADER_USER_INFO: "Gendry",
            HTTP_HEADER_SIGNATURE: ""
        }
        t1 = client.fetch_user_token(headers, "SecurityClientTest")
        time.sleep(0.6)
        t2 = client.fetch_user_token(headers, "SecurityClientTest")
        nt.assert_not_equal(t1, t2)

    def test_appcache_no_target(self):
        client = self.get_client()
        t1 = client.fetch_app_token("SecurityClientTest")
        t2 = client.fetch_app_token("SecurityClientTest")
        nt.assert_equal(t1, t2)

    def test_appcache_same_target(self):
        client = self.get_client()
        t1 = client.fetch_app_token("Target")
        t2 = client.fetch_app_token("Target")
        nt.assert_equal(t1, t2)

    def test_appcache_diff_target(self):
        client = self.get_client()
        t1 = client.fetch_app_token("Target")
        t2 = client.fetch_app_token("NotSecurityClientTest")
        nt.assert_not_equal(t1, t2)

    def test_appcache_expire(self):
        client = self.get_client()
        t1 = client.fetch_app_token("SecurityClientTest")
        time.sleep(0.6)
        t2 = client.fetch_app_token("SecurityClientTest")
        nt.assert_not_equal(t1, t2)


class TestEzSecurityClientMockMode(EzSecurityTest):
    def setUp(self):
        super(TestEzSecurityClientMockMode, self).setUp()
        self.ez_props[ezbake.security.client.USE_MOCK_KEY] = "true"
        self.ez_props[ezbake.security.client.MOCK_USER_DN] = "Test User"

    def test_mock_mode_no_dn(self):
        self.ez_props[ezbake.security.client.MOCK_USER_DN] = None
        client = self.get_client()
        headers = {}
        nt.assert_raises(RuntimeError, client.fetch_user_token, headers)

    def test_mock_mode(self):
        client = self.get_client()
        headers = {}
        token = client.fetch_user_token(headers)
        nt.assert_is_not_none(token)

    def test_mock_mode_validate_received(self):
        client = self.get_client()
        nt.assert_true(client.validate_received_token(EzSecurityToken()))
