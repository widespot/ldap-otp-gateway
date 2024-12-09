import logging

import ldaptor.protocols.pureldap
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.proxybase import ProxyBase
from twisted.internet import defer

from .gateway_filter.base_gateway_filter import BaseGatewayFilter
from .otp.base_otp import BaseOtp
from .otp_extractor.base_otp_extractor import BaseOTPExtractor

OTP_REQUEST_ATTR = "otp"
GATEWAY_PASS_THROUGH_ATTR = "pass_through"
GATEWAY_PASS_THROUGH_FORWARD_VALUE = b"forward"
GATEWAY_PASS_THROUGH_FILTER_VALUE = b"filter"


class OtpProxy(ProxyBase):

    def __init__(self, otp_backend, otp_extractor, gateway_filter=None):
        super().__init__()

        assert otp_backend is not None and isinstance(otp_backend, BaseOtp)
        assert otp_extractor is not None and isinstance(otp_extractor, BaseOTPExtractor)
        assert gateway_filter is None or isinstance(gateway_filter, BaseGatewayFilter)

        self.otp_backend = otp_backend
        self.otp_extractor = otp_extractor
        self.gateway_filter = gateway_filter

    def connectionLost(self, reason):
        super().connectionLost(reason)

    def handleProxiedResponse(self, response, request, controls):
        logging.info("Front end request => " + repr(request))
        logging.info("Backend response => " + repr(response))

        r = response
        if isinstance(request, ldaptor.protocols.pureldap.LDAPBindRequest):

            pass_through = None
            try:
                pass_through = getattr(request, GATEWAY_PASS_THROUGH_ATTR)
            except AttributeError:
                error = ("Something really bad happened while trying to load the pass through behaviour after"
                         "passing the request to the backend")
                logging.error(error)
                r = pureldap.LDAPBindResponse(
                    ldaperrors.LDAPUnknownError.resultCode,
                    errorMessage=error)

            if pass_through == GATEWAY_PASS_THROUGH_FILTER_VALUE:
                if not isinstance(response, ldaptor.protocols.pureldap.LDAPBindResponse):
                    error = f"Unknown LDAP response type to initial LDAPBindRequest request: {response.__class__}"
                    logging.error(error)
                    r = pureldap.LDAPBindResponse(
                        ldaperrors.LDAPUnknownError.resultCode,
                        errorMessage=error)

                if response.resultCode == 0:
                    r = self.otp_bind(request, response)

        if r != response:
            logging.info("Gateway modified response => " + repr(r))

        return defer.succeed(r)

    def otp_bind(self, request: ldaptor.protocols.pureldap.LDAPBindRequest, response):
        user = request.dn.decode()
        password = request.auth.decode()
        try:
            otp = getattr(request, OTP_REQUEST_ATTR).decode()
        except AttributeError:
            error = ("Something really bad happened. OTP couldn't be loaded back by the gateway"
                     "from request after forwarding it to the backend")
            logging.error(error)
            return pureldap.LDAPBindResponse(ldaperrors.LDAPUnknownError.resultCode,
                                             errorMessage=error)

        logging.debug(f"otp_bind user:{user}, password:{password}, otp={otp}")

        try:
            if self.otp_backend.verify(user, password, otp):
                if response is not None:
                    logging.info("Successful OTP verification, forwarding backend response")
                    return response

                logging.info("Successful OTP verification but no backend response to forward. "
                             "Generating an empty success response instead")
                return pureldap.LDAPBindResponse(ldaperrors.Success.resultCode)
            else:
                logging.warning("Failed OTP verification.")
                return pureldap.LDAPBindResponse(ldaperrors.LDAPInvalidCredentials.resultCode)
        except Exception as e:
            logging.error("Error while performing OTP verification.")
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
            if self.gateway_filter is not None and self.gateway_filter.ignore(request):
                setattr(request, GATEWAY_PASS_THROUGH_ATTR, GATEWAY_PASS_THROUGH_FORWARD_VALUE)
            else:

                try:
                    [password, otp] = self.otp_extractor.extract(request)
                except Exception as e:
                    # Return an "Invalid credentials" response if the extraction failed
                    logging.warning(e)
                    reply(pureldap.LDAPBindResponse(ldaperrors.LDAPInvalidCredentials.resultCode,
                                                    errorMessage=str(e)))
                    return None

                setattr(request, GATEWAY_PASS_THROUGH_ATTR, GATEWAY_PASS_THROUGH_FILTER_VALUE)
                setattr(request, OTP_REQUEST_ATTR, otp)
                request.auth = password

        return defer.succeed((request, controls))
