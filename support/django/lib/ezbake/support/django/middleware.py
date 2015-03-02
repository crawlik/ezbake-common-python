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

import logging

from django.http import HttpResponseForbidden

from ezbake.base.thriftapi.ttypes import ProxyUserToken, X509Info
from ezbake.configuration.EzConfiguration import EzConfiguration
from ezbake.security.client import (EzSecurityClient, HTTP_HEADER_SIGNATURE,
    HTTP_HEADER_USER_INFO)
from ezbake.security.util import (current_time_millis, serialize_to_json,
    deserialize_from_json)

from constants import MOCK_USER_DN

EZSECURITY_HEADER_USER_INFO = 'HTTP_EZB_VERIFIED_USER_INFO'
EZSECURITY_HEADER_SIGNATURE = 'HTTP_EZB_VERIFIED_SIGNATURE'

logger = logging.getLogger("ezbake.support.django.%s" % __name__)


def date_handler(obj):
    """
    Helps serialize python objects to JSON by taking the isoformat for 
    datetime objects.
    """
    return obj.isoformat() if hasattr(obj, 'isoformat') else obj


def has_proxy_user_token(request):
    """
    Returns True if the header has fields 'HTTP_EZB_VERIFIED_USER_INFO' and 
    'HTTP_EZB_VERIFIED_SIGNATURE'.

    :param request:
    :return:
    """

    h_user_info = EZSECURITY_HEADER_USER_INFO
    h_sig = EZSECURITY_HEADER_SIGNATURE

    return True if (h_user_info in request.META) and \
                   (h_sig in request.META) else False

class BaseEzSecurityMiddleware(object):

    def __init__(self):

        self.ez_config = EzConfiguration()
        self.ez_props = self.ez_config.getProperties()
        self.ez_security_client = EzSecurityClient(self.ez_props)


class EzSecurityDebugMiddleware(BaseEzSecurityMiddleware):
    """
    EzSecurityDebugMiddleware injects ProxyUserToken that expires in 1 hour
    from the time of the request into the header HTTP_EZB_VERIFIED_USER_INFO,
    and its signature into HTTP_EZB_VERIFIED_SIGNATURE if settings.DEPLOY_ENV
    is set to DEV.

    """

    def make_token(self):
        x509 = X509Info(
            subject = self.ez_props.get(MOCK_USER_DN)
        )
        token = ProxyUserToken(
            x509=x509,
            issuedBy="EzSecurity",
            issuedTo="EFE",
            notAfter=current_time_millis() + 720000 # 720000 = 12 mins
        )
        return token

    def process_request(self, request):
        """
        Injects the ProxyUserPrincipal and its signature into the headers.

        :param request: instance of Django's HttpRequest
        :return: returns the request object with the injected ProxyUserToken, and signature.
        """

        if not has_proxy_user_token(request):

            token = self.make_token()
            dn = serialize_to_json(token)
            signature = self.ez_security_client._mock_service_sign(dn)

            if EZSECURITY_HEADER_USER_INFO not in request.META:
                request.META[EZSECURITY_HEADER_USER_INFO] = dn

            if EZSECURITY_HEADER_SIGNATURE not in request.META:
                request.META[EZSECURITY_HEADER_SIGNATURE] = signature
            return


class EzSecurityMiddleware(BaseEzSecurityMiddleware):

    def process_request(self, request):
        """
        Processes requests by inspecting its headers and looking for serialized
        versions of ProxyUserToken, and it's signature. Only if the
        ProxyUserToken and it's signature is valid, the request is allowed to
        go through. If not, a HttpResponse with 403 is returned
        (HttpResponseForbidden).

        :param request: HttpRequest
        :return:
        """
        logger.debug("EzSecurityMiddleware.process_request Entered")

        # check that we have a token, and forbid further access if not found
        if not has_proxy_user_token(request):
            return HttpResponseForbidden()

        # we already have ProxyUserToken. Now validate it.
        logger.debug(
            "Request contains ProxyUserToken and ProxyPrincipal's signature.")
        dn = None
        try:
            dn = request.META[EZSECURITY_HEADER_USER_INFO]
            sig = request.META[EZSECURITY_HEADER_SIGNATURE]
            headers = {
                HTTP_HEADER_USER_INFO: dn,
                HTTP_HEADER_SIGNATURE: sig
            }
            is_valid = self.ez_security_client.validate_current_request(
                headers)
        except Exception, e:
            logger.error("Unable to validate current request: %s" % e.message)
            is_valid = False

        if not is_valid:
            logger.info("Request with invalid token was received. Returning 403 Response. (DN: %s)" % dn)
            return HttpResponseForbidden()

        # check that the token is valid for the current time
        json_token = deserialize_from_json(dn)
        if current_time_millis() > json_token['notAfter']:
            return HttpResponseForbidden()


        logger.debug("EzSecurityMiddleware.process_request Exitted.")
