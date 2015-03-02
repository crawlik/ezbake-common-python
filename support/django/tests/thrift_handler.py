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
import base64
import traceback

import OpenSSL.crypto as ossl
from ezbake.security import util
from ezsecurity.constants import SERVICE_NAME

from ezbakeBaseTypes.ttypes import (EzSecurityToken, TokenRequest, TokenType,
                                    EzSecurityPrincipal, ValidityCaveats, CommunityMembership)
from ezbakeBaseAuthorizations.ttypes import Authorizations

logger = logging.getLogger(__name__)

fh = logging.FileHandler("/tmp/foo.baz")
fh.setLevel(logging.DEBUG)
sh = logging.StreamHandler()
sh.setLevel(logging.DEBUG)
logger.addHandler(sh)
logger.addHandler(fh)

logger.setLevel(logging.DEBUG)


class EzSecurityHandler(object):
    def __init__(self, rsa):
        self.app_name = "common_services"
        self.service_name = SERVICE_NAME
        self.rsa = ossl.load_privatekey(ossl.FILETYPE_PEM, rsa)

    @staticmethod
    def ping():
        return True

    def requestToken(self, request, signature):
        """
        Responds with an instance of EzSecurityToken that is specific to the
        request type.

        :param request:
        :param signature:
        :return:
        """

        token = None
        assert isinstance(request, TokenRequest), \
            "request object is not an instance of TokenRequest"

        try:
            # user info
            if request.type == TokenType.USER:
                logger.debug("Token requested of type USER.")

                # prep EzSecurityPrincipal
                proxyToken = getattr(request.proxyPrincipal, 'proxyToken', "")
                token_principal = EzSecurityPrincipal(
                    principal= proxyToken,
                    name="Joe User",
                    externalID="joe.user"
                )

                # prep Authorizations
                formal_authorizations = ['A', 'B', 'C']
                authorizations = Authorizations(
                    formalAuthorizations=formal_authorizations
                )

                # prep externalProjectGroups
                external_project_groups = {
                    'EzBake': ['Core'],
                    '42six': ['Dev', 'Emp'],
                    'Nothing': ['groups', 'group2']
                }

                # prep externalCommunities
                community_membership = CommunityMembership(
                    name='EzBake',
                    type='office',
                    organization='EzBake',
                    topics=['topic1', 'topic2'],
                    regions=['region1', 'region2', 'region3'],
                    flags={
                        'ACIP': True
                    },
                    groups=[]
                )
                external_communities = {'EzBake': community_membership}

                # prep EzSecurityToken
                token = EzSecurityToken(
                    tokenPrincipal=token_principal,
                    authorizations=authorizations,
                    citizenship="USA",
                    authorizationLevel="low",
                    organization="EzBake",
                    externalProjectGroups=external_project_groups,
                    externalCommunities=external_communities
                )

            # app info
            elif request.type == TokenType.APP:
                logger.debug("Token requested of type APP.")

                # respond with app information
                if request.securityId == 'SecurityClientTest':

                    # prep EzSecurityPrincipal
                    token_principal = EzSecurityPrincipal(
                        principal=request.securityId
                    )

                    # prep Authorizations
                    formal_authorizations = ['A', 'B', 'C']
                    authorizations = Authorizations(
                        formalAuthorizations=formal_authorizations
                    )

                    # prep AuthorizationLevel
                    authorization_level = 'low'

                else:

                    # prep Authorizations
                    formal_authorizations = []
                    authorizations = Authorizations(
                        formalAuthorizations=formal_authorizations
                    )

                    # prep AuthorizationLevel
                    authorization_level = ''
                    token_principal = None

                token = EzSecurityToken(
                    tokenPrincipal=token_principal,
                    authorizations=authorizations,
                    authorizationLevel=authorization_level
                )

            # prep ValidityCaveats
            if token:
                validity_caveats = ValidityCaveats(
                    issuedFor=request.targetSecurityId,
                    issuedTo=request.securityId,
                    notAfter=util.current_time_millis() + 600 * 1000
                )
                token.validity = validity_caveats
                data = util.serialize_token(token)
                token.validity.signature = base64.b64encode(ossl.sign(self.rsa, data, 'sha256'))
                token.validate()
                return token

        except Exception, e:
            traceback.format_exc()
            logger.exception("ERROR: Unable to process: %s" % e.message)
            raise
