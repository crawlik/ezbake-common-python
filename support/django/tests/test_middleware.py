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

import datetime
import mock
import unittest

from django.http import HttpRequest

from ezbake.support.django.middleware import (date_handler,
  has_proxy_user_token, BaseEzSecurityMiddleware, EzSecurityDebugMiddleware,
  EzSecurityMiddleware, EZSECURITY_HEADER_SIGNATURE, EZSECURITY_HEADER_USER_INFO)


from ezbake.base.thriftapi.ttypes import ProxyUserToken
from ezbake.security.util import current_time_millis, serialize_to_json



class MiddlewareUtilsTestCase(unittest.TestCase):

    def test_date_handler(self):
        """
        date_handler unittest.
        """
        # setup
        now = datetime.datetime.now()

        # test
        self.assertEqual(now.isoformat(), date_handler(now))
        self.assertEqual({}, date_handler({}))

    def test_has_proxy_user_token(self):
        """
        has_proxy_user_token unittest with valid headers.
        """
        # setup
        m_request = mock.MagicMock(spec=HttpRequest)
        m_request.META = {
            EZSECURITY_HEADER_USER_INFO: '',
            EZSECURITY_HEADER_SIGNATURE: ''
        }

        # test
        self.assertTrue(has_proxy_user_token(m_request))

    def test_has_proxy_user_token_empty(self):
        """
        has_proxy_user_token unittest with no valid headers.
        """
        # setup
        m_request = mock.MagicMock(spec=HttpRequest)
        m_request.META = {}

        # test
        self.assertFalse(has_proxy_user_token(m_request))

class BaseEzSecurityMiddlewareTestCase(unittest.TestCase):

    def test_initialization(self):
        """
        Tests initialization of BaseEzSecurityMiddleware.
        """
        # setup
        middleware = BaseEzSecurityMiddleware()

        # test
        self.assertTrue(hasattr(middleware, 'ez_config'))
        self.assertTrue(hasattr(middleware, 'ez_props'))
        self.assertTrue(hasattr(middleware, 'ez_security_client'))

class EzSecurityDebugMiddlewareTestCase(unittest.TestCase):

    def test_process_request(self):

        # setup
        m_request = mock.MagicMock(spec=HttpRequest)
        m_request.META = {}
        middleware = EzSecurityDebugMiddleware()
        middleware.process_request(m_request)

        # test
        self.assertIn(EZSECURITY_HEADER_USER_INFO, m_request.META)
        self.assertIn(EZSECURITY_HEADER_SIGNATURE, m_request.META)

class EzSecurityMiddlewareTestCase(unittest.TestCase):

    def __set_headers(self, m_request):
        """
        For testing purpose, this method setups the mocked request.
        """
        m_request.META = {}
        m_request.META[EZSECURITY_HEADER_USER_INFO] = serialize_to_json(
            ProxyUserToken(notAfter=current_time_millis() + 10000))
        m_request.META[EZSECURITY_HEADER_SIGNATURE] = \
            "EZSECURITY_HEADER_SIGNATURE"
        return m_request

    def test_process_request_positive(self):
        """
        Tests positive case of EzSecurityMiddleware with right headers.
        """
        # setup
        m_request = self.__set_headers(mock.MagicMock(spec=HttpRequest))
        middleware = EzSecurityMiddleware()
        middleware.ez_security_client = mock.Mock()
        middleware.ez_security_client.validateCurrentRequest.return_value = \
            True
        response = middleware.process_request(m_request)

        # test
        self.assertIsNone(response)


    def test_process_request_negative(self):
        """
        Tests negative case of EzSecurityMiddleware with wrong headers.
        """
        # setup
        # settings = mock.Mock()
        with mock.patch('ezbake.support.django.middleware.HttpResponseForbidden') as m_HttpResponseForbidden:

            m_request = self.__set_headers(mock.MagicMock(spec=HttpRequest))
            middleware = EzSecurityMiddleware()
            middleware.ez_security_client = mock.Mock()
            middleware.ez_security_client.validate_current_request.return_value = \
                False
            response = middleware.process_request(m_request)

            # test
            self.assertEqual(response, m_HttpResponseForbidden())
