import json
import os
import unittest
from unittest.mock import MagicMock, patch

from ldap_otp_gateway.gateway_filter.ignore_static_user_list import GatewayFilter


class TestGatewayFilter(unittest.TestCase):

    def test_init_no_arg_no_env(self):
        a = GatewayFilter()
        self.assertEqual(a.ignore_list, [])

    @patch.dict(os.environ, {"GATEWAY_FILTER_IGNORE_USERS": '["mytemp"]'},
                     clear=True)  # why need clear=True explained here https://stackoverflow.com/a/67477901/248616
    def test_init_no_arg_but_env(self):
        a = GatewayFilter()
        self.assertEqual(a.ignore_list, ["mytemp"])

    @patch.dict(os.environ, {"GATEWAY_FILTER_IGNORE_USERS": '[NotJson,"]'},
                clear=True)  # why need clear=True explained here https://stackoverflow.com/a/67477901/248616
    def test_init_no_arg_but_wrong_json_env(self):
        with self.assertRaises(json.decoder.JSONDecodeError):
            GatewayFilter()

    def test_init_uppercase(self):
        a = GatewayFilter(["aA"])
        self.assertEqual(a.ignore_list, ["aa"])

    def test_ignore(self):
        a = GatewayFilter(["aA"])
        request = MagicMock()
        request.dn = b"AA"
        self.assertTrue(a.ignore(request))

    def test_dont_ignore(self):
        a = GatewayFilter(["aA"])
        request = MagicMock()
        request.dn = b"Ab"
        self.assertFalse(a.ignore(request))


if __name__ == '__main__':
    unittest.main()
