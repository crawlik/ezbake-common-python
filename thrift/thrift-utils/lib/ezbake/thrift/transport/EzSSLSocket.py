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
Created on Tue Nov 12 08:25:15 2013

@author: jhastings
"""
import os
import re
import ssl
import logging

from thrift.transport.TTransport import TTransportException
from thrift.transport import TSocket
import thrift.transport.TSSLSocket as TSSL

from ezbake.configuration.helpers import SecurityConfiguration


class TVerifyingSSLSocket(object):
    """Class used to verify SSL peer certificates after connecting

    Overriding the _verify_cn method will allow you to override the
    CN settings
    """
    def __init__(self, socket, verify_pattern=None):
        self.socket = socket
        self.verify_pattern = None
        if verify_pattern:
            self.verify_pattern = re.compile(verify_pattern)

    def _is_cn_valid(self, cert_cn):
        return self.verify_pattern.match(cert_cn) is not None

    def _validate_cert(self, handle=None):
        """
        internal method to validate the peer's SSL certificate, and to check
        that the  commonName is set

        raises TTransportException if the certificate fails validation."""
        if handle is None and isinstance(self.socket.handle, ssl.SSLSocket):
            handle = self.socket.handle
        cert = handle.getpeercert()
        self.socket.peercert = cert
        if 'subject' not in cert:
            raise TTransportException(
                type=TTransportException.NOT_OPEN,
                message='No SSL certificate found from %s:%s' %
                        (self.socket.host, self.socket.port))

        fields = cert['subject']
        for field in fields:
            # ensure structure we get back is what we expect
            if not isinstance(field, tuple):
                continue
            cert_pair = field[0]
            if len(cert_pair) < 2:
                continue
            cert_key, cert_value = cert_pair[0:2]
            if cert_key != 'commonName':
                continue
            cert_cn = cert_value
            if cert_cn is not None:
                if self.verify_pattern is not None:
                    if self._is_cn_valid(cert_cn):
                        self.is_valid = True
                        return
                else:
                    # success
                    self.socket.is_valid = True
                    return
            else:
                raise TTransportException(
                    type=TTransportException.UNKNOWN,
                    message='Application name we connected to "%s" doesn\'t '
                            'match application name provided commonName' % cert_cn)
        raise TTransportException(
            type=TTransportException.UNKNOWN,
            message='Could not validate SSL certificate from host "%s". '
                    'Cert=%s' % (self.socket.host, cert))


class TSSLSocket(TVerifyingSSLSocket, TSSL.TSSLSocket):
    """This Socket overrides the Thrift TSSLSocket by adding a custom verify method

    It uses the TVerifyingSSLSocket class to provide CN verification
    """

    def __init__(self,
                 config=None,
                 host='localhost',
                 port=9090,
                 validate=True,
                 unix_socket=None,
                 verify_pattern=None,
                 ca_certs=None,
                 cert=None,
                 key=None):
        if config is not None:
            # use values from config if not passed
            sc = SecurityConfiguration(config)
            if ca_certs is None:
                ca_certs = sc.getTrustedSslCerts()
            if cert is None:
                cert = sc.getSslCertificate()
            if key is None:
                key = sc.getPrivateKey()

        TSSL.TSSLSocket.__init__(self, host=host, port=port, validate=validate, ca_certs=ca_certs, certfile=cert,
                                 keyfile=key, unix_socket=unix_socket)
        TVerifyingSSLSocket.__init__(self, self, verify_pattern)


class TSSLServerSocket(TVerifyingSSLSocket, TSSL.TSSLServerSocket):
    """
    SSL implementation of TServerSocket

    This uses the ssl module's wrap_socket() method to provide SSL
    negotiated encryption.
    """

    def __init__(self,
                 host=None,
                 port=None,
                 config=None,
                 ca_certs=None,
                 cert=None,
                 key=None,
                 unix_socket=None,
                 ciphers=None,
                 verify_pattern=None,
                 validate=True):
        """Initialize a TSSLServerSocket

        Raises an IOError exception if any of the ca_certs, cert or key file is
        None, not present or unreadable.
        """
        if config is not None:
            # use values from config if not passed
            sc = SecurityConfiguration(config)
            if ca_certs is None:
                ca_certs = sc.getTrustedSslCerts()
            if cert is None:
                cert = sc.getSslCertificate()
            if key is None:
                key = sc.getPrivateKey()
            if ciphers is None:
                ciphers = sc.getSslCiphers()
        if ca_certs is None or not os.access(ca_certs, os.R_OK):
            raise IOError('Certificate Authority ca_certs file "%s" is not'
                          ' readable, cannot validate SSL certificates.' %
                          ca_certs)
        if cert is None or not os.access(cert, os.R_OK):
            raise IOError('Server Certificate certs file "%s" is not'
                          ' readable, cannot validate SSL certificates.' %
                          cert)
        if key is None or not os.access(key, os.R_OK):
            raise IOError('Server Key file "%s" is not'
                          ' readable, cannot validate SSL certificates.' %
                          key)
        TSSL.TSSLServerSocket.__init__(self, host=host, port=port, unix_socket=unix_socket, certfile=cert)
        TVerifyingSSLSocket.__init__(self, self, verify_pattern)
        self.ca_certs = ca_certs
        self.cert = cert
        self.key = key
        self.ciphers = ciphers
        self.validate = validate
        if not self.validate:
            self.cert_reqs = ssl.CERT_NONE
        else:
            self.cert_reqs = ssl.CERT_REQUIRED

    def accept(self):
        plain_client, addr = self.handle.accept()
        try:
            client = ssl.wrap_socket(plain_client,
                                     ca_certs=self.ca_certs,
                                     certfile=self.cert,
                                     keyfile=self.key,
                                     server_side=True,
                                     cert_reqs=self.cert_reqs,
                                     ssl_version=self.SSL_VERSION,
                                     do_handshake_on_connect=True,
                                     ciphers=self.ciphers)
        except ssl.SSLError as ex:
            logging.error('SSL ERROR: %s' % str(ex))
            # failed handshake/ssl wrap, close socket to client
            plain_client.close()
            # We can't raise the exception, because it kills most TServer
            # derived serve() methods.
            # Instead, return None, and let the TServer instance deal with it
            # in other exception handling.  (but TSimpleServer dies anyway)
            return None
        result = TSocket.TSocket()
        result.setHandle(client)
        if self.validate:
            self._validate_cert(client)
        return result
