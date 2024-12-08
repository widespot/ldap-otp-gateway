# One Time Password (OTP) with LDAP
> Easy MFA using OTP using existing standard LDAP architecture

Your LDAP doesn't support One Time Password? No problem. 
With the LDAP OTP proxy, integrate any OTP server with an existing LDPA setup.

![architecture.drawio.png](doc%2Farchitecture.drawio.png)

The end user simply concatenate the password and OTP instead of using the password alone

## Quickstart
Run the LDAP OTP proxy
```shell
pip install
# Set the environment variable (see bellow) and run the service
ldap-top-proxy
# or
python -m ldap_otp_proxy.run
```
And test
```shell
# Unsecure
ldapwhoami -x -H ldap://localhost:10389 -D "cn=admin,dc=example,dc=com" -w password123456
# With SSL
ldapwhoami -x -H ldaps://localhost:10636 -D "cn=admin,dc=example,dc=com" -w password123456
```

### Using Docker
```yaml
services:
  ldap: ...
  otp: ...
  ldap-otp-proxy:
    image: ghcr.io/widespot/ldap-otp-proxy:v0.1.0
    ports:
      - 10389:10389
      - 10636:10636
    environment:
      LDAP_HOST: 'ldap'
      OTP_HOST: 'otp'
    volumes:
      # put the server.key.pem and server.crt.pem files here
      - ./certs:/opt/ldap-otp-proxy/certs
```

## Full stack example
See the [example directory](./example)

## Environment configuration
See [config.py](src/ldap_otp_proxy/config.py) file for more details

| variable      | default     | description                                               |
|---------------|-------------|-----------------------------------------------------------|
| LDAP_HOST     | `localhost` | host of the backend LDAP server                           |
| LDAP_PORT     | `389`       | port for the unsecure endpoint of the LDAP backend        |
| LDAP_SSL_PORT | `636`       | port for the SSL endpoint of the LDAP backend             |
| OTP_PROTOCOL  | `http`      | protocol for the OTP backend. `http` and `https` accepted |
| OTP_HOST      | `localhost` | host of the backend OTP service                           |
| OTP_PORT      | `8080`      |                                                           |
| OTP_ENDPOINT  | `openotp/`  |                                                           |

## Dev
```shell
python3 -m venv ./venv
source venv/bin/activate
poetry install
ldap-top-proxy
# or
python -m ldap_otp_proxy.run
```
