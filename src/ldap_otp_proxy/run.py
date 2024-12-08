import logging
from functools import partial

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
from twisted.internet import protocol, reactor, ssl

from . import config
from .otp_proxy import OtpProxy

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

OTP_REQUEST_ATTR = "otp"


def ldapBindRequestRepr(self):
    l = []
    l.append('version={0}'.format(self.version))
    l.append('dn={0}'.format(repr(self.dn)))
    l.append('auth=****')
    if self.tag != self.__class__.tag:
        l.append('tag={0}'.format(self.tag))
    l.append('sasl={0}'.format(repr(self.sasl)))
    return self.__class__.__name__ + '(' + ', '.join(l) + ')'


pureldap.LDAPBindRequest.__repr__ = ldapBindRequestRepr


def run():
    logging.info("Starting LDAP OTP proxy")

    backend_connection_string = f'tcp:{config.LDAP_HOST}:{config.LDAP_PORT}'
    logging.info(f"- using unsecure backend: {backend_connection_string}")
    backend_connector = partial(
        connectToLDAPEndpoint,
        reactor,
        backend_connection_string,
        LDAPClient)

    backend_connection_string_ssl = f'ssl:{config.LDAP_HOST}:{config.LDAP_SSL_PORT}'
    logging.info(f"- using SSL backend: {backend_connection_string_ssl}")
    backend_connector_ssl = partial(
        connectToLDAPEndpoint,
        reactor,
        backend_connection_string_ssl,
        LDAPClient)

    def build_protocol():
        proto = OtpProxy()
        proto.clientConnector = backend_connector
        proto.use_tls = False
        return proto

    def build_protocol_ssl():
        proto = OtpProxy()
        proto.clientConnector = backend_connector_ssl
        proto.use_tls = False
        return proto

    factory = protocol.ServerFactory()
    factory_ssl = protocol.ServerFactory()

    factory.protocol = build_protocol
    factory_ssl.protocol = build_protocol_ssl
    logging.info(f"- prepare unsecure frontend")
    reactor.listenTCP(config.LDAP_PROXY_PORT, factory)
    logging.info(f"- prepare SSL frontend")
    reactor.listenSSL(config.LDAP_PROXY_SSL_PORT, factory_ssl,
                      ssl.DefaultOpenSSLContextFactory(
                          config.LDAP_PROXY_SSL_KEY_PATH, config.LDAP_PROXY_SSL_CERT_PATH)
                      )
    logging.info(f"RUN !")
    reactor.run()


if __name__ == '__main__':
    run()
