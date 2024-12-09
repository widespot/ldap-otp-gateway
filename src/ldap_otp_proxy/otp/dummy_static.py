import logging
import os

from .base_otp import BaseOtp


OTP_STATIC_CODE = os.environ.get('OTP_STATIC_CODE', '123456')


class Otp(BaseOtp):

    def __init__(self):
        self.dummy_static = OTP_STATIC_CODE
        logging.debug(f"dummy_static={self.dummy_static}")

    def verify(self, username, password, otp) -> bool:
        return otp == self.dummy_static
