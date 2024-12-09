import logging

import ldaptor.protocols.pureldap
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.proxybase import ProxyBase
from twisted.internet import defer

from . import config

OTP_REQUEST_ATTR = "otp"


class OtpProxy(ProxyBase):

    def __init__(self):
        super().__init__()
        from .otp.soap_rcdevs import Otp
        self.otp = Otp()

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

        try:
            if self.otp.verify(user, password, otp):
                if response is not None:
                    logging.info("Successful OTP verification, forwarding backend response")
                    return response

                logging.info("Successful OTP verification but no backend response to forward. "
                             "Generating an empty success response instead")
                return pureldap.LDAPBindResponse(ldaperrors.Success.resultCode)
            else:
                logging.info("Failed OTP verification.")
                return pureldap.LDAPBindResponse(ldaperrors.LDAPInvalidCredentials.resultCode)
        except Exception as e:
            logging.info("Error while performing OTP verification.")
            logging.error(e)
            return pureldap.LDAPBindResponse(ldaperrors.LDAPUnknownError.resultCode, errorMessage="")

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
