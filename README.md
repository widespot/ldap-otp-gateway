# One Time Password (OTP) with LDAP
> Easy MFA using OTP using existing standard LDAP architecture

Your LDAP doesn't support One Time Password? No problem. 
With the LDAP OTP gateway, integrate any OTP server with an existing LDPA setup.

![architecture.drawio.png](doc%2Farchitecture.drawio.png)

The end user simply concatenate the password and OTP instead of using the password alone

## Quickstart
Run the LDAP OTP gateway (see [CLI arguments](#CLI-arguments) + [Run configuration](#run-configuration) for more)
```shell
# 1. Install package
pip install
# 2. Optionally configure using the environment variable
#export LDAP_HOST=custom-host
# 3. run the service using executable
ldap-otp-gateway
# 3 bis. or the python modue
python -m ldap_otp_gateway.run
```
And test
```shell
# Unsecure
ldapwhoami -x -H ldap://localhost:10389 -D "cn=admin,dc=example,dc=com" -w password123456
# With SSL
ldapwhoami -x -H ldaps://localhost:10636 -D "cn=admin,dc=example,dc=com" -w password123456
```

### Using Docker
```shell
docker run \
  -p 10389:10389 -p 10636:10636 \
  ghcr.io/widespot/ldap-otp-gateway
```
Or using `docker compose`
```yaml
services:
  ldap: ...
  otp: ...
  ldap-otp-gateway:
    image: ghcr.io/widespot/ldap-otp-gateway
    ports:
      - 10389:10389
      - 10636:10636
    environment:
      LDAP_HOST: 'ldap'
      OTP_HOST: 'otp'
    volumes:
      # put the server.key.pem and server.crt.pem files here
      # See Run configuration and SSL considerations sections
      - ./certs:/opt/ldap-otp-gateway/certs
```

## Full stack example
See the [example directory](./example)

## CLI arguments
both the builtin `ldap-otp-gateway` CLI executable, and the
manual `python -m ldap_otp_gateway.run` module executions accepts the following parameters
```
usage: ldap-otp-gateway [-h] [--load-dotenv]

Run the LDAP OTP gateway.

options:
  -h, --help     show this help message and exit
  --load-dotenv  use python-dotenv to load environment variables.
```

## Run configuration
The run configuration works with environment variables. 
See [config.py](src/ldap_otp_gateway/config.py) file for actual implementation and more details in in-code comments.

| variable                   | default                     | description                                                                                                                                                                                                    |
|----------------------------|-----------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| LDAP_HOST                  | `localhost`                 | host of the backend LDAP server                                                                                                                                                                                |
| LDAP_PORT                  | `389`                       | port for the unsecure endpoint of the LDAP backend                                                                                                                                                             |
| LDAP_SSL_PORT              | `636`                       | port for the SSL endpoint of the LDAP backend                                                                                                                                                                  |
| LDAP_GATEWAY_PORT          | `10389`                     |                                                                                                                                                                                                                |
| LDAP_GATEWAY_SSL_PORT      | `10636`                     |                                                                                                                                                                                                                |
| LDAP_GATEWAY_SSL_KEY_PATH  | `./certs/server.key.pem`    | absolute or relative (to cwd) path to the gateway SSL signing key. Self signed certificate generated if none SSL file provided. See [SSL endpoints considerations section](#ssl-endpoints-considerations)      |                                                                               
| LDAP_GATEWAY_SSL_CERT_PATH | `./certs/server.crt.pem`    | absolute or relative (to cwd) path to the gateway SSL certificate. Self signed certificate generated if none SSL file provided. See [SSL endpoints considerations section](#ssl-endpoints-considerations)      |                                                                                                                                            
| OTP_BACKEND_MODULE_NAME    | `.otp_backend.dummy_static` | relative or absolute Python module containing an `OtpBackend` class that extends `BaseOtpBackend` and implements the OTP Backend behaviour. see [OTP Backends configuration section](#OTP-Backends)            |
| OTP_EXTRACTOR_MODULE_NAME  | `.otp_extractor.suffix`     | relative or absolute Python module containing an `OtpExtractor` class that extends `BaseOtpExtractor` and implements the OTP extracting mechanism. see [OTP Extractors configuration section](#OTP-Extractors) |
| GATEWAY_FILTER_MODULE_NAME | `None`                      | relative or absolute Python module containing a `GatewayFilter` class that extends `BaseGatewayFilter` and implements the pass through selection. see [Pass through section](#gateway-pass-through-behaviour)  |

### OTP Backends
Two OTP backends are provided, but any custom behaviour can be added. It must be provided
as a `OtpBackend` class, extending
[`BaseOtpBackend`](src/ldap_otp_gateway/otp_backend/base_otp_backend.py)

Built in backends:
* **Dummy static (`ldap_otp_gateway.otp_backend.dummy_static`)** *[default behaviour]*

  Dummy insecure static unique code, for testing purpose. ([see source](src/ldap_otp_gateway/otp_backend/dummy_static.py))

  | variable        | default  | description  |
  |-----------------|----------|--------------|
  | OTP_STATIC_CODE | `123456` | expected OTP |

* **RCdevs SOAP (`ldap_otp_gateway.otp_backend.rcdevs_soap`)**

  RCDevs came up with an ugly implementation of OTP based on aging SOAP.
  The service is named WebAdm and is an ugly obfuscated "free" implementation bundled with
  a lot of fancy but useless stuffs. If you too are stuck with that product, sorry for you.
  We at least do our best to ease your life. ([see source](src/ldap_otp_gateway/otp_backend/rcdevs_soap.py))

  | variable      | default     | description                                               |
  |---------------|-------------|-----------------------------------------------------------|
  | OTP_PROTOCOL  | `http`      | protocol for the OTP backend. `http` and `https` accepted |
  | OTP_HOST      | `localhost` | host of the backend OTP service                           |
  | OTP_PORT      | `8080`      |                                                           |
  | OTP_ENDPOINT  | `openotp/`  |                                                           |

### OTP Extractors
One OTP extractor is provided, but any custom behaviour can be added. It must be provided
as a `OtpExtractor` class, extending
[`BaseOtpExtractor`](src/ldap_otp_gateway/otp_extractor/base_otp_extractor.py).
There is one function to implement, that is taking
an LDAP request as input, and must return the `password` + `otp`.

Built in extractor:
* **Suffix (`ldap_otp_gateway.otp_extractor.suffix`)** *[default behaviour]*

  Expects the OTP concatenated directly after the password, as suffix. ([see source](src/ldap_otp_gateway/otp_extractor/suffix.py))

### Gateway pass through behaviour
This LDAP gateway can either forward or filter the LDAP requests it receives.
It can be useful to directly pass to the backend requests made by users that are not using OTP.

One gateway filter is provided, but any custom behaviour can be added. It must be provided
as a `GatewayFilter` class, extending
[`BaseGatewayFilter`](src/ldap_otp_gateway/gateway_filter/base_gateway_filter.py).
There is one function to implement, that is taking an
LDAP request as input, and must return a boolean, whether it is to be forwarded as is or fitered
for OTP.

Built in gateway filter *(default behaviour is None)*:
* **Static user list (`ldap_otp_gateway.gateway_filter.ignore_static_user_list`)**

  Directly forwards LDAP requests to backend for a static list of user DN.
  The search in the list is case-insensitive ([see source](src/ldap_otp_gateway/gateway_filter/ignore_static_user_list.py))


### SSL endpoints considerations
The unsecure gateway endpoint will hit the insecure LDAP endpoint while the SSL access point 
of the gateway will target the SSL side of the LDAP backed.

## Development and contributing
```shell
python3 -m venv ./venv
source venv/bin/activate
poetry install --with peer
python -m unittest discover -s tests/unit
ldap-otp-gateway
# or
python -m ldap_otp_gateway.run
# or use the debug mode of IDE to execute src/ldap_otp_gateway/run.py
```
