import logging

import ldaptor.protocols.pureldap
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.proxybase import ProxyBase
import requests
from twisted.internet import defer

from . import config

OTP_REQUEST_ATTR = "otp"


class OtpProxy(ProxyBase):

    def connectionLost(self, reason):
        super().connectionLost(reason)

    def handleProxiedResponse(self, response, request, controls):
        """
        Log the representation of the responses received.
        """
        logging.info("Request => " + repr(request))
        logging.info("Response => " + repr(response))

        r = response
        if isinstance(request, ldaptor.protocols.pureldap.LDAPBindRequest):
            if not isinstance(response, ldaptor.protocols.pureldap.LDAPBindResponse):
                error = f"Unknown LDAP response type to initial LDAPBindRequest request: {response.__class__}"
                logging.error(error)
                r = pureldap.LDAPBindResponse(
                    ldaperrors.LDAPUnknownError.resultCode,
                    errorMessage=error)

            if response.resultCode == 0:
                otp = getattr(request, OTP_REQUEST_ATTR, None)
                if otp is None:
                    error = f"Error getting OTP from request after forwarding it to the backend"
                    logging.error(error)
                    r = pureldap.LDAPBindResponse(
                        ldaperrors.LDAPUnknownError.resultCode,
                        errorMessage=error)
                else:
                    r = self.otp_bind(request, response)

        if r != response:
            logging.info("Modified response => " + repr(r))

        return defer.succeed(r)

    def otp_bind(self, request: ldaptor.protocols.pureldap.LDAPBindRequest, response):
        user = request.dn.decode()
        otp = (getattr(request, OTP_REQUEST_ATTR, request.auth[-6:])).decode()
        password = (request.auth if hasattr(request, OTP_REQUEST_ATTR) else request.auth[:-6]).decode()
        logging.debug(f"otp_bind user:{user}, password:{password}, otp={otp}")

        uri = f"{config.OTP_PROTOCOL}://{config.OTP_HOST}:{config.OTP_PORT}/{config.OTP_ENDPOINT}"
        logging.debug(f"uri={uri}")
        data = (
            "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsi=\"http://www.w3.org/1999/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/1999/XMLSchema\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
            "<SOAP-ENV:Header/>"
            "<SOAP-ENV:Body>"
            "<m:openotpSimpleLogin xmlns:m=\"urn:openotp\">"
            f"<m:username xsi:type=\"xsd:string\">{user}</m:username>"
            "<m:domain xsi:type=\"xsd:string\"/>"
            f"<m:anyPassword xsi:type=\"xsd:string\">{password}{otp}</m:anyPassword>"
            "<m:client xsi:type=\"xsd:string\">ldapsearch</m:client>"
            "<m:source xsi:type=\"xsd:string\"/>"
            "<m:settings xsi:type=\"xsd:string\">ChallengeMode=No</m:settings>"
            "<m:options xsi:type=\"xsd:string\">NOVOICE,-U2F,LDAPDN</m:options>"
            "<m:context xsi:type=\"xsd:string\"/><m:retryId xsi:type=\"xsd:string\"/>"
            "</m:openotpSimpleLogin>"
            "</SOAP-ENV:Body>"
            "</SOAP-ENV:Envelope>")
        logging.debug(f"data={data}")
        r = requests.post(
            uri,
            headers={"Content-Type": "text/xml"},
            data=data)

        try:
            logging.debug(r.raw)
            r.raise_for_status()
            if response is not None:
                return response
            return pureldap.LDAPBindResponse(ldaperrors.Success.resultCode)
        except Exception as e:
            logging.error(e)
            pureldap.LDAPBindResponse(ldaperrors.LDAPInvalidCredentials.resultCode)

    def handleBeforeForwardRequest(self, request, controls, reply):
        """
        Override to modify request and/or controls forwarded on to the proxied server.
        Must return a tuple of request, controls or a deferred that fires the same.
        Return `None` or a deferred that fires `None` to bypass forwarding the
        request to the proxied server.  In this case, any response can be sent to the
        client via `reply(response)`.
        """
        if isinstance(request, ldaptor.protocols.pureldap.LDAPBindRequest):
            if len(request.auth) < 6:
                reply(pureldap.LDAPBindResponse(ldaperrors.LDAPInvalidCredentials.resultCode,
                                                errorMessage="Missing OTP credentials"))

                return None

            if config.OTP_BIND:
                reply(self.otp_bind(request, None))
                return None

            # remove & backup OTP from request auth before it is passed to proxied LDAP
            setattr(request, OTP_REQUEST_ATTR, request.auth[-6:])
            request.auth = request.auth[:-6]

        return defer.succeed((request, controls))
