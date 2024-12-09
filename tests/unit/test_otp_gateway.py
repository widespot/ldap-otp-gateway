import unittest
from unittest.mock import MagicMock, patch

from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.pureldap import LDAPBindRequest, LDAPBindResponse
from twisted.internet.defer import Deferred

from ldap_otp_gateway import OtpGateway
from ldap_otp_gateway.otp_backend.base_otp_backend import BaseOtpBackend
from ldap_otp_gateway.otp_backend.dummy_static import OtpBackend as DummyStaticOtp
from ldap_otp_gateway.gateway_filter.base_gateway_filter import BaseGatewayFilter
from ldap_otp_gateway.otp_extractor.base_otp_extractor import BaseOTPExtractor
from ldap_otp_gateway.otp_extractor.suffix import OtpExtractor as SuffixOtpExtractor

from ldap_otp_gateway.otp_gateway import OTP_REQUEST_ATTR, GATEWAY_PASS_THROUGH_FORWARD_VALUE, GATEWAY_PASS_THROUGH_ATTR


class TestOtpGateway(unittest.TestCase):

    def test_init_no_arg(self):
        with self.assertRaises(TypeError):
            # noinspection PyArgumentList
            OtpGateway()

    def test_init_no_second_positional_arg(self):
        with self.assertRaises(TypeError):
            # noinspection PyArgumentList
            OtpGateway(None)

    def test_init_no_otp_backend(self):
        with self.assertRaises(TypeError):
            # noinspection PyArgumentList
            OtpGateway(otp_extractor=None)

    def test_init_none_ldap_otp_backend_and_extractor(self):
        with self.assertRaises(AssertionError):
            OtpGateway(None, None)

    def test_init_wrong_otp_backend_type(self):
        with self.assertRaises(AssertionError):
            OtpGateway(object(), None)

    def test_init_none_otp_extractor(self):
        with self.assertRaises(AssertionError):
            OtpGateway(DummyStaticOtp(), None)

    def test_handleBeforeForwardRequest_no_bind_request(self):
        proxy = OtpGateway(DummyStaticOtp(), SuffixOtpExtractor())
        request = object()
        controls = object()
        reply = MagicMock()
        r = proxy.handleBeforeForwardRequest(request, controls, reply)

        self.assertIsInstance(r, Deferred)
        self.assertEqual(r.result, (request, controls))
        self.assertEqual(reply.call_count, 0)

    def test_handleBeforeForwardRequest_with_bind_request(self):
        password = b'password'
        otp = b'123456'
        extractor = SuffixOtpExtractor()
        extractor.extract = MagicMock(return_value=[password, otp])
        proxy = OtpGateway(DummyStaticOtp(), extractor)
        request = LDAPBindRequest()
        controls = object()
        reply = MagicMock()
        r = proxy.handleBeforeForwardRequest(request, controls, reply)

        extractor.extract.assert_called_once_with(request)
        reply.assert_not_called()
        self.assertEqual(request.auth, password)
        self.assertEqual(getattr(request, OTP_REQUEST_ATTR), otp)
        self.assertIsInstance(r, Deferred)
        self.assertEqual(r.result, (request, controls))

    @patch('ldap_otp_gateway.otp_backend.base_otp_backend.BaseOtpBackend')
    @patch('ldap_otp_gateway.otp_extractor.base_otp_extractor.BaseOTPExtractor')
    @patch('ldap_otp_gateway.gateway_filter.base_gateway_filter.BaseGatewayFilter')
    def test_handleBeforeForwardRequest_fail_extract(self, BaseOtpBackendMock, BaseOtpExtractorMock, BaseGatewayFilterMock):
        password = b'password'
        error_message = 'error message'

        otp_backend = BaseOtpBackend()
        otp_extractor = BaseOTPExtractor()
        exception = Exception(error_message)
        otp_extractor.extract = MagicMock(side_effect=exception)
        gateway_filter = BaseGatewayFilter()

        proxy = OtpGateway(otp_backend, otp_extractor, gateway_filter)
        request = LDAPBindRequest()
        request.auth = password
        controls = object()
        reply = MagicMock()
        r = proxy.handleBeforeForwardRequest(request, controls, reply)

        # Assert extractor called once
        otp_extractor.extract.assert_called_once_with(request)
        # Assert no OTP set
        self.assertEqual(hasattr(request, OTP_REQUEST_ATTR), False)
        # Assert no pass through set
        self.assertEqual(hasattr(request, GATEWAY_PASS_THROUGH_ATTR), False)
        # Assert password unchanged
        self.assertEqual(request.auth, password)
        # assert return is None
        self.assertIsNone(r)
        # But reply has been called
        reply.assert_called_once()
        reply_arg = reply.call_args_list[0][0][0]
        self.assertIsInstance(reply_arg, LDAPBindResponse)
        self.assertEqual(reply_arg.resultCode, ldaperrors.LDAPInvalidCredentials.resultCode)
        self.assertEqual(request.auth, password)
        self.assertEqual(hasattr(request, OTP_REQUEST_ATTR), False)

    @patch('ldap_otp_gateway.otp_backend.base_otp_backend.BaseOtpBackend')
    @patch('ldap_otp_gateway.otp_extractor.base_otp_extractor.BaseOTPExtractor')
    @patch('ldap_otp_gateway.gateway_filter.base_gateway_filter.BaseGatewayFilter')
    def test_handleBeforeForwardRequest_filter_ignore(self, BaseOtpBackendMock, BaseOtpExtractorMock, BaseGatewayFilterMock):
        otp_backend = BaseOtpBackend()
        otp_extractor = BaseOTPExtractor()
        gateway_filter = BaseGatewayFilter()
        gateway_filter.ignore = MagicMock(return_value=True)

        proxy = OtpGateway(otp_backend, otp_extractor, gateway_filter)

        password = b'password'
        request = LDAPBindRequest()
        request.auth = password
        controls = object()
        reply = MagicMock()
        r = proxy.handleBeforeForwardRequest(request, controls, reply)

        # Assert filter called once
        gateway_filter.ignore.assert_called_once_with(request)
        # Assert password unchanged
        self.assertEqual(request.auth, password)
        # Assert no OTP set
        self.assertEqual(hasattr(request, OTP_REQUEST_ATTR), False)
        # Assert pass through set to forward value
        self.assertEqual(getattr(request, GATEWAY_PASS_THROUGH_ATTR), GATEWAY_PASS_THROUGH_FORWARD_VALUE)
        # Assert no reply
        reply.assert_not_called()
        # but a return value
        self.assertIsInstance(r, Deferred)
        self.assertEqual(r.result, (request, controls))


if __name__ == '__main__':
    unittest.main()
