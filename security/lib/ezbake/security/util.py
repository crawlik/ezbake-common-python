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
Created on Wed Nov 13 16:01:14 2013

@author: jhastings
"""
import base64
from collections import OrderedDict
import json
import logging
import struct
import time
import OpenSSL.crypto as ossl

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5

import thrift.transport.TTransport
import thrift.protocol.TJSONProtocol

from ezbake.base.thriftapi.ttypes import TokenType


current_time_millis = lambda: int(round(time.time() * 1000))

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler())


def __pack_string(string, can_be_none=False):
    if can_be_none:
        if string is None or string == '':
            return ''
    return struct.pack('!%ds' % len(string), string)


def __pack_long(number, can_be_none=False):
    if can_be_none:
        if number is None:
            return '0'

    if number is None:
        raise Exception('A number must be given!')

    return __pack_string(str(number))


def __java_bool_value(value):
    if value:
        return 'true'
    return 'false'


def serialize_token_request(token):
    buf = ''

    proxy_principal = token.proxyPrincipal
    if proxy_principal is not None:
        buf += __pack_string(proxy_principal.proxyToken)
        buf += __pack_string(proxy_principal.signature)
    elif token.tokenPrincipal is not None:
        buf += serialize_token(token.tokenPrincipal)

    buf += __pack_string(TokenType._VALUES_TO_NAMES[token.type])
    buf += __pack_string(token.securityId)
    buf += __pack_string(token.targetSecurityId, can_be_none=True)
    buf += __pack_long(token.timestamp)

    exclude_authorizations = token.excludeAuthorizations
    if exclude_authorizations is not None:
        auth_list = list(exclude_authorizations)
        auth_list.sort()
        for auth in auth_list:
            buf += __pack_string(auth)

    return buf


def serialize_token(token):
    buf = ''             # bytes()

    validity = token.validity
    buf += __pack_string(validity.issuedTo)
    buf += __pack_string(validity.issuedFor, can_be_none=True)
    buf += __pack_long(validity.notAfter)
    buf += __pack_long(validity.notBefore, can_be_none=True)
    buf += __pack_long(validity.issuedTime, can_be_none=True)

    buf += __pack_string(TokenType._VALUES_TO_NAMES[token.type])

    token_principal = token.tokenPrincipal
    buf += __pack_string(token_principal.principal)
    buf += __pack_string(token_principal.issuer, can_be_none=True)
    if token_principal.requestChain is not None:
        for chain in token_principal.requestChain:
            buf += __pack_string(chain)

    buf += __pack_string(token.authorizationLevel, can_be_none=True)
    authorizations = token.authorizations
    if authorizations is not None:

        formal_authorizations = authorizations.formalAuthorizations
        if formal_authorizations is not None:
            auth_list = list(formal_authorizations)
            auth_list.sort()
            for auth in auth_list:
                buf += __pack_string(auth)

        external_community_authorizations = authorizations.externalCommunityAuthorizations
        if external_community_authorizations is not None:
            auth_list = list(external_community_authorizations)
            auth_list.sort()
            for auth in auth_list:
                buf += __pack_string(auth)

        platform_object_authorizations = authorizations.platformObjectAuthorizations
        if platform_object_authorizations is not None:
            auth_list = list(platform_object_authorizations)
            auth_list.sort()
            for auth in auth_list:
                buf += __pack_string(str(auth))

    external_project_groups = token.externalProjectGroups
    if external_project_groups is not None:
        external_project_groups = OrderedDict(sorted(external_project_groups.items(), key=lambda t: t[0]))
        token.externalProjectGroups = external_project_groups
        for key, value in external_project_groups.iteritems():
            buf += __pack_string(key)
            for group in value:
                buf += __pack_string(group)

    external_communities = token.externalCommunities
    if external_communities is not None:
        for key, community_membership in external_communities.iteritems():
            buf += __pack_string(community_membership.name)
            buf += __pack_string(community_membership.type)
            buf += __pack_string(community_membership.organization, can_be_none=True)

            groups = community_membership.groups
            if groups is not None:
                groups.sort()
                for group in groups:
                    buf += __pack_string(group)

            topics = community_membership.topics
            if topics is not None:
                topics.sort()
                for topic in topics:
                    buf += __pack_string(topic)

            regions = community_membership.regions
            if regions is not None:
                regions.sort()
                for region in regions:
                    buf += __pack_string(region)

            flags = community_membership.flags
            if flags is not None:
                o_flags = OrderedDict(sorted(flags.items(), key=lambda t: t[0]))
                for key1, value in o_flags.iteritems():
                    buf += __pack_string(key1)
                    buf += __pack_string(__java_bool_value(value))

    buf += __pack_string(__java_bool_value(token.validForExternalRequest), can_be_none=True)
    buf += __pack_string(token.citizenship, can_be_none=True)
    buf += __pack_string(token.organization, can_be_none=True)

    return buf


def __verify(token, pubkey):
    log = logging.getLogger(__name__)

    expires = token.validity.notAfter
    if expires > current_time_millis():
        log.info("token expiration looks ok ({0} > {1})".format(expires, current_time_millis()))
        log.info("verifying the signature")
        return verify_signature(rawdata=serialize_token(token),
                                signature=base64.b64decode(token.validity.signature),
                                cert=pubkey)
    else:
        log.info("expiration is bad ({0} > {1})".format(expires, current_time_millis()))
        return False


def verify(token, pubkey, owner, target=None):
    log = logging.getLogger(__name__)

    valid = False
    log.debug("verifying token {0}".format(token))
    if target is not None:
        log.info("Target not None, verifying target security ID")
        if token.validity.issuedFor == target:
            log.info("Target security ID matches the passed target")
            valid = __verify(token, pubkey)
    elif token.validity.issuedTo == owner:
        log.info("Verifying token for owner: {0}".format(owner))
        valid = __verify(token, pubkey)
    else:
        log.info("Not verifying token because target is none and the security ID doesn't match the owner")

    log.info("Is Token Valid: %s" % valid)
    return valid


def verify_signed_dn(dn, signature, pub_key):
    return verify_signature(dn, base64.b64decode(signature), pub_key)


def verify_proxy_token_signature(proxy_user_token, signature, pubKey):
    """
    Verifies that the proxy user token is valid with the signature and public key.

    :param proxy_user_token: instance of ProxyUserToken
    :param signature: String containing signature of ProxyUserToken
    :param pubKey: Public Key used for signing.
    :return:
    """
    decoded_signature = base64.b64decode(signature)
    return verify_signature(proxy_user_token, decoded_signature, pubKey)


def verify_signature(rawdata, signature, cert):
    # Not having x509 anymore. Use PyCrypto to verify instead
    #cert = ossl.load_certificate(ossl.FILETYPE_PEM, cert)
    #ossl.verify(cert, signature, rawdata, 'sha256')

    # verify response validity first
    key = RSA.importKey(cert)
    digest = SHA256.new(rawdata)
    verifier = PKCS1_v1_5.new(key)

    return verifier.verify(digest, signature)


def serialize_to_json(thrift_obj):
    """
    Uses TSimpleJSONProtocol to serialize the given thrift_obj into a simple,
    (non-proprietary) JSON object.

    :param thrift_obj: Any Thrift Object
    :return: JSON string
    """
    transportOut = thrift.transport.TTransport.TMemoryBuffer()
    factory = thrift.protocol.TJSONProtocol.TSimpleJSONProtocolFactory()
    protocolOut = factory.getProtocol(transportOut)
    thrift_obj.write(protocolOut)
    bytes = transportOut.getvalue()

    return bytes


def deserialize_from_json(json_string):
    """
    Uses the built-in JSON library to decode the JSON into a python dictionary,
    which is then returned.

    :param json_string:
    :return:
    """

    return json.loads(json_string)


def ssl_sign(data, private_key):

    """
    Sign some data using OpenSSL, and the application's certificate
    @return the base64 encodeded signature
    """
    key = ossl.load_privatekey(ossl.FILETYPE_PEM, private_key)
    return base64.b64encode(ossl.sign(key, data, 'sha256'))
