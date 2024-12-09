import importlib
import logging
import os

# BACKEND SETTINGS
LDAP_HOST = os.getenv('LDAP_HOST', 'localhost')
LDAP_PORT = os.getenv('LDAP_PORT', '389')
LDAP_SSL_PORT = os.getenv('LDAP_SSL_PORT', '636')

# FRONTEND SETTINGS
try:
    LDAP_GATEWAY_PORT = int(os.getenv('LDAP_GATEWAY_PORT', '10389'))
except ValueError:
    raise ValueError(f'LDAP_GATEWAY_PORT must be an integer value. found {os.getenv("LDAP_GATEWAY_PORT")} instead')

try:
    LDAP_GATEWAY_SSL_PORT = int(os.getenv('LDAP_GATEWAY_SSL_PORT', '10636'))
except ValueError:
    raise ValueError(f'LDAP_GATEWAY_SSL_PORT must be an integer value. found {os.getenv("LDAP_GATEWAY_SSL_PORT")} instead')

LDAP_GATEWAY_SSL_KEY_PATH = os.getenv('LDAP_GATEWAY_SSL_KEY_PATH', './certs/server.key.pem')
LDAP_GATEWAY_SSL_CERT_PATH = os.getenv('LDAP_GATEWAY_SSL_CERT_PATH', './certs/server.crt.pem')

generate_certificates = False
if not os.path.isabs(LDAP_GATEWAY_SSL_KEY_PATH):
    LDAP_GATEWAY_SSL_KEY_PATH = os.path.join(os.getcwd(), LDAP_GATEWAY_SSL_KEY_PATH)
if not os.path.exists(LDAP_GATEWAY_SSL_KEY_PATH):
    generate_certificates = True
    os.makedirs(os.path.dirname(LDAP_GATEWAY_SSL_KEY_PATH), exist_ok=True)

if not os.path.isabs(LDAP_GATEWAY_SSL_CERT_PATH):
    LDAP_GATEWAY_SSL_CERT_PATH=os.path.join(os.getcwd(), LDAP_GATEWAY_SSL_CERT_PATH)
if not os.path.exists(LDAP_GATEWAY_SSL_CERT_PATH):
    if not generate_certificates:
        raise Exception("SSL cert path doesn't exists but a key file was provided. Please provide none or both")
    os.makedirs(os.path.dirname(LDAP_GATEWAY_SSL_CERT_PATH), exist_ok=True)
elif generate_certificates:
    raise Exception("SSL cert path exists but a key file don't. Please provide none or both")

if generate_certificates:
    from OpenSSL import crypto, SSL

    logging.info("SSL cert and key files not found. Generating it ...")
    def cert_gen(
            emailAddress="emailAddress",
            commonName="commonName",
            countryName="NT",
            localityName="localityName",
            stateOrProvinceName="stateOrProvinceName",
            organizationName="organizationName",
            organizationUnitName="organizationUnitName",
            serialNumber=0,
            validityStartInSeconds=0,
            validityEndInSeconds=10 * 365 * 24 * 60 * 60):
        # can look at generated file using openssl:
        # openssl x509 -inform pem -in selfsigned.crt -noout -text
        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)
        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = countryName
        cert.get_subject().ST = stateOrProvinceName
        cert.get_subject().L = localityName
        cert.get_subject().O = organizationName
        cert.get_subject().OU = organizationUnitName
        cert.get_subject().CN = commonName
        cert.get_subject().emailAddress = emailAddress
        cert.set_serial_number(serialNumber)
        cert.gmtime_adj_notBefore(validityStartInSeconds)
        cert.gmtime_adj_notAfter(validityEndInSeconds)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha512')
        with open(LDAP_GATEWAY_SSL_CERT_PATH, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        with open(LDAP_GATEWAY_SSL_KEY_PATH, "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

    cert_gen()


# OTP SETTINGS
OTP_BACKEND_MODULE_NAME = os.getenv('OTP_BACKEND_MODULE_NAME', 'ldap_otp_gateway.otp_backend.dummy_static')
OTP_BACKEND = getattr(importlib.import_module(OTP_BACKEND_MODULE_NAME), 'OtpBackend')
logging.info(f"OTP backend loaded: {OTP_BACKEND_MODULE_NAME}")
# Experimental
OTP_BIND = False
