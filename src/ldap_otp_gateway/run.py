import logging
from functools import partial

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
from twisted.internet import protocol, reactor, ssl

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

from . import config
from .gateway_filter.ignore_static_user_list import GatewayFilter
from .otp_extractor.suffix import OtpExtractor
from .otp_gateway import OtpGateway

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
    logging.info("Starting LDAP OTP gateway ...")

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

    otp_backend = config.OTP_BACKEND()
    otp_extractor = OtpExtractor()
    gateway_filter = GatewayFilter()

    def build_protocol():
        proto = OtpGateway(otp_backend, otp_extractor=otp_extractor, gateway_filter=gateway_filter)
        proto.clientConnector = backend_connector
        proto.use_tls = False
        return proto

    def build_protocol_ssl():
        proto = OtpGateway(otp_backend, otp_extractor=otp_extractor, gateway_filter=gateway_filter)
        proto.clientConnector = backend_connector_ssl
        proto.use_tls = False
        return proto

    factory = protocol.ServerFactory()
    factory_ssl = protocol.ServerFactory()

    factory.protocol = build_protocol
    factory_ssl.protocol = build_protocol_ssl
    logging.info(f"- prepare unsecure frontend listening on port :{config.LDAP_GATEWAY_PORT}")
    reactor.listenTCP(config.LDAP_GATEWAY_PORT, factory)
    logging.info(f"- prepare SSL frontend listening on port :{config.LDAP_GATEWAY_SSL_PORT}")
    reactor.listenSSL(config.LDAP_GATEWAY_SSL_PORT, factory_ssl,
                      ssl.DefaultOpenSSLContextFactory(
                          config.LDAP_GATEWAY_SSL_KEY_PATH, config.LDAP_GATEWAY_SSL_CERT_PATH)
                      )
    logging.info(f"RUN !")
    reactor.run()


if __name__ == '__main__':
    run()
