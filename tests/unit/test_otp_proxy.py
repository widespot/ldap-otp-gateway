import unittest
from unittest.mock import MagicMock, patch

from ldaptor.protocols.ldap import ldaperrors
from ldaptor.protocols.pureldap import LDAPBindRequest, LDAPBindResponse
from twisted.internet.defer import Deferred

from ldap_otp_proxy import OtpProxy
from ldap_otp_proxy.otp.base_otp import BaseOtp
from ldap_otp_proxy.otp.dummy_static import Otp as DummyStaticOtp
from ldap_otp_proxy.gateway_filter.base_gateway_filter import BaseGatewayFilter
from ldap_otp_proxy.otp_extractor.base_otp_extractor import BaseOTPExtractor
from ldap_otp_proxy.otp_extractor.suffix import OtpExtractor as SuffixOtpExtractor

from ldap_otp_proxy.otp_proxy import OTP_REQUEST_ATTR, GATEWAY_PASS_THROUGH_FORWARD_VALUE, GATEWAY_PASS_THROUGH_ATTR


class TestOtpProxy(unittest.TestCase):

    def test_init_no_arg(self):
        with self.assertRaises(TypeError):
            # noinspection PyArgumentList
            OtpProxy()

    def test_init_no_second_positional_arg(self):
        with self.assertRaises(TypeError):
            # noinspection PyArgumentList
            OtpProxy(None)

    def test_init_no_otp_backend(self):
        with self.assertRaises(TypeError):
            # noinspection PyArgumentList
            OtpProxy(otp_extractor=None)

    def test_init_none_ldap_otp_backend_and_extractor(self):
        with self.assertRaises(AssertionError):
            OtpProxy(None, None)

    def test_init_wrong_otp_backend_type(self):
        with self.assertRaises(AssertionError):
            OtpProxy(object(), None)

    def test_init_none_otp_extractor(self):
        with self.assertRaises(AssertionError):
            OtpProxy(DummyStaticOtp(), None)

    def test_handleBeforeForwardRequest_no_bind_request(self):
        proxy = OtpProxy(DummyStaticOtp(), SuffixOtpExtractor())
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
        proxy = OtpProxy(DummyStaticOtp(), extractor)
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

    def test_handleBeforeForwardRequest_fail_extract(self):
        password = b'password'
        extractor = SuffixOtpExtractor()
        exception = Exception()
        extractor.extract = MagicMock(side_effect=exception)
        proxy = OtpProxy(DummyStaticOtp(), extractor)
        request = LDAPBindRequest()
        request.auth = password
        controls = object()
        reply = MagicMock()
        r = proxy.handleBeforeForwardRequest(request, controls, reply)

        # Assert extractor called once
        extractor.extract.assert_called_once_with(request)
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

    @patch('ldap_otp_proxy.otp.base_otp.BaseOtp')
    @patch('ldap_otp_proxy.otp_extractor.base_otp_extractor.BaseOTPExtractor')
    @patch('ldap_otp_proxy.gateway_filter.base_gateway_filter.BaseGatewayFilter')
    def test_handleBeforeForwardRequest_filter_ignore(self, BaseOtpBackendMock, BaseOtpExtractorMock, BaseGatewayFilterMock):
        otp_backend = BaseOtp()
        otp_extractor = BaseOTPExtractor()
        gateway_filter = BaseGatewayFilter()
        gateway_filter.ignore = MagicMock(return_value=True)

        proxy = OtpProxy(otp_backend, otp_extractor, gateway_filter)

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
