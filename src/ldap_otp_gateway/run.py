import argparse
import logging
import os
from functools import partial

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
from twisted.internet import protocol, reactor, ssl

from .gateway_filter.ignore_static_user_list import GatewayFilter
from .otp_extractor.suffix import OtpExtractor
from .otp_gateway import OtpGateway

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
logging.basicConfig()


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
    parser = argparse.ArgumentParser(description='Run the LDAP OTP gateway.')
    parser.add_argument('--load-dotenv', action='store_true',
                        help='use python-dotenv to load environment variables. ')

    args = parser.parse_args()
    if args.load_dotenv:
        try:
            # noinspection PyUnresolvedReferences
            import dotenv
        except ModuleNotFoundError:
            raise Exception("python-dotenv package not found. It's not part of the package dependency and you need "
                            "to install it manually before using --load-dotenv argument.")

        dotenv_path = os.path.join(os.getcwd(), '.env')
        logger.info(f"Loading environment from {dotenv_path} ...")
        dotenv.load_dotenv(dotenv_path)

    logger.info("Start run configuration")

    from . import config

    logger.info("Now starting LDAP OTP gateway ...")

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
        proto = OtpGateway(config.OTP_BACKEND, otp_extractor=config.OTP_EXTRACTOR, gateway_filter=config.GATEWAY_FILTER)
        proto.clientConnector = backend_connector
        proto.use_tls = False
        return proto

    def build_protocol_ssl():
        proto = OtpGateway(config.OTP_BACKEND, otp_extractor=config.OTP_EXTRACTOR, gateway_filter=config.GATEWAY_FILTER)
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
