import logging

import ldaptor.protocols.pureldap
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.ldap.proxybase import ProxyBase
from twisted.internet import defer

from . import config
# TODO dynamic
from .gateway_filter.ignore_static_user_list import GatewayFilter
# TODO dynamic
from .otp_extractor.suffix import OtpExtractor

OTP_REQUEST_ATTR = "otp"
GATEWAY_PASS_THROUGH_ATTR = "pass_through"
GATEWAY_PASS_THROUGH_FORWARD_VALUE = b"forward"
GATEWAY_PASS_THROUGH_FILTER_VALUE = b"filter"


class OtpProxy(ProxyBase):

    def __init__(self):
        super().__init__()

        # TODO init in config because OtpProxy is init at each request
        # TODO have the otp as init parameter
        self.otp = config.OTP()
        self.otp_extractor = OtpExtractor()
        self.gateway_filter = GatewayFilter()

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
            logging.info("Modified response => " + repr(r))

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
            if self.gateway_filter.ignore(request):
                setattr(request, GATEWAY_PASS_THROUGH_ATTR, GATEWAY_PASS_THROUGH_FORWARD_VALUE)
            else:
                setattr(request, GATEWAY_PASS_THROUGH_ATTR, GATEWAY_PASS_THROUGH_FILTER_VALUE)

                try:
                    # remove & backup OTP from request auth before it is passed to proxied LDAP
                    [password, otp] = self.otp_extractor.extract(request)
                    setattr(request, OTP_REQUEST_ATTR, otp)
                    request.auth = password
                except Exception as e:
                    logging.error(e)
                    reply(pureldap.LDAPBindResponse(ldaperrors.LDAPInvalidCredentials.resultCode,
                                                    errorMessage=str(e)))
                    return None

        return defer.succeed((request, controls))
