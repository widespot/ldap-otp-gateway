import string
import random
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

from ldap_otp_gateway.otp_backend.rcdevs_soap import OtpBackend, check_response, normalize


SUCCESS_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:openotp">
<SOAP-ENV:Body>
<ns1:openotpSimpleLoginResponse>
    <code>1</code>
    <error/>
    <message>Authentication success</message>
    <data/>
    <concat>8</concat>
</ns1:openotpSimpleLoginResponse>
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>
"""


class TestOtpBackend(unittest.TestCase):
    @patch('requests.post')
    def test_check_response(self, post_patch):
        username = ''.join(random.sample(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=random.randint(6,12)))
        password = ''.join(random.sample(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=random.randint(6,12)))
        otp = ''.join(random.sample(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=6))
        post_return_mock = MagicMock()
        response_text_mock = PropertyMock(return_value=SUCCESS_RESPONSE)
        type(post_return_mock).text = response_text_mock
        post_patch.return_value = post_return_mock
        t = OtpBackend()
        v, error = t.verify(username, password, otp)
        self.assertTrue(v)
        self.assertIsNone(error)
        self.assertEqual(1, post_patch.call_count)
        self.assertEqual(post_patch.call_args.args, ('http://localhost:8080/openotp/',))
        self.assertIn('data', post_patch.call_args.kwargs)
        self.assertEqual(post_patch.call_args.kwargs['data'], f'<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/1999/XMLSchema-instance" xmlns:xsd="http://www.w3.org/1999/XMLSchema" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><SOAP-ENV:Header/><SOAP-ENV:Body><m:openotpSimpleLogin xmlns:m="urn:openotp"><m:username xsi:type="xsd:string">{username}</m:username><m:domain xsi:type="xsd:string"/><m:anyPassword xsi:type="xsd:string">{password}{otp}</m:anyPassword><m:client xsi:type="xsd:string">ldapsearch</m:client><m:source xsi:type="xsd:string"/><m:settings xsi:type="xsd:string">ChallengeMode=No</m:settings><m:options xsi:type="xsd:string">NOVOICE,-U2F,LDAPDN</m:options><m:context xsi:type="xsd:string"/><m:retryId xsi:type="xsd:string"/></m:openotpSimpleLogin></SOAP-ENV:Body></SOAP-ENV:Envelope>')
        self.assertEqual(1, response_text_mock.call_count)


class TestNormalize(unittest.TestCase):
    def test_success_without_opening(self):
        x = "<a>\n <b>\n </b>\n </a>"
        y = "<?xml version=\"1.0\" ?><a><b/></a>"
        self.assertEqual(y, normalize(x))

    def test_success_with_opening(self):
        x = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><a>\n <b>\n </b>\n </a>"
        y = "<?xml version=\"1.0\" ?><a><b/></a>"
        self.assertEqual(y, normalize(x))


class TestCheckResponse(unittest.TestCase):

    def test_success(self):
        check_response(SUCCESS_RESPONSE)

    def test_wrong_code(self):
        with self.assertRaises(Exception) as e:
            check_response("""<?xml version="1.0" encoding="UTF-8"?>
                    <SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="urn:openotp">
                    <SOAP-ENV:Body>
                    <ns1:openotpSimpleLoginResponse>
                        <code>0</code>
                        <error/>
                        <message>Authentication success</message>
                        <data/>
                        <concat>8</concat>
                    </ns1:openotpSimpleLoginResponse>
                    </SOAP-ENV:Body>
                    </SOAP-ENV:Envelope>
                    """)
        self.assertTrue(str(e.exception).startswith("Expected response code to be \"1\" but got 0 instead"))


if __name__ == '__main__':
    unittest.main()
