import os

# BACKEND SETTINGS
LDAP_HOST = os.getenv('LDAP_HOST', 'localhost')
LDAP_PORT = os.getenv('LDAP_PORT', '389')
LDAP_SSL_PORT = os.getenv('LDAP_SSL_PORT', '636')

# FRONTEND SETTINGS
try:
    LDAP_PROXY_PORT = int(os.getenv('LDAP_PROXY_PORT', '10389'))
except ValueError:
    raise ValueError(f'LDAP_PROXY_PORT must be an integer value. found {os.getenv("LDAP_PROXY_PORT")} instead')

try:
    LDAP_PROXY_SSL_PORT = int(os.getenv('LDAP_PROXY_SSL_PORT', '10636'))
except ValueError:
    raise ValueError(f'LDAP_PROXY_SSL_PORT must be an integer value. found {os.getenv("LDAP_PROXY_SSL_PORT")} instead')

#LDAP_PROXY_SSL_KEY_PATH = '/Users/raphaeljoie/Workspace/github.com/widespot/ldap-otp-proxy/example/certs/server.key.pem'
#LDAP_PROXY_SSL_CERT_PATH = '/Users/raphaeljoie/Workspace/github.com/widespot/ldap-otp-proxy/example/certs/server.crt.pem'
LDAP_PROXY_SSL_KEY_PATH = './certs/server.key.pem'
LDAP_PROXY_SSL_CERT_PATH = './certs/server.crt.pem'

generate_certificates = False
if not os.path.isabs(LDAP_PROXY_SSL_KEY_PATH):
    LDAP_PROXY_SSL_KEY_PATH = os.path.join(os.getcwd(), LDAP_PROXY_SSL_KEY_PATH)
if not os.path.exists(LDAP_PROXY_SSL_KEY_PATH):
    generate_certificates = True
    os.makedirs(os.path.dirname(LDAP_PROXY_SSL_KEY_PATH), exist_ok=True)

if not os.path.isabs(LDAP_PROXY_SSL_CERT_PATH):
    LDAP_PROXY_SSL_CERT_PATH=os.path.join(os.getcwd(), LDAP_PROXY_SSL_CERT_PATH)
if not os.path.exists(LDAP_PROXY_SSL_CERT_PATH):
    if not generate_certificates:
        raise Exception("SSL cert path doesn't exists but a key file was provided. Please provide none or both")
    os.makedirs(os.path.dirname(LDAP_PROXY_SSL_CERT_PATH), exist_ok=True)
elif generate_certificates:
    raise Exception("SSL cert path exists but a key file don't. Please provide none or both")

if generate_certificates:
    from OpenSSL import crypto, SSL

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
        with open(LDAP_PROXY_SSL_CERT_PATH, "wt") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
        with open(LDAP_PROXY_SSL_KEY_PATH, "wt") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))

    cert_gen()


# OTP SETTINGS
OTP_PROTOCOL = os.getenv('OTP_PROTOCOL', 'http')
OTP_HOST = os.getenv('OTP_HOST', 'localhost')
OTP_PORT = os.getenv('OTP_PORT', '8080')
OTP_ENDPOINT = os.getenv('OTP_ENDPOINT', 'openotp/')
# Experimental
OTP_BIND = False
