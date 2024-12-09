import logging
import os

from .base_otp_backend import BaseOtpBackend


OTP_STATIC_CODE = os.environ.get('OTP_STATIC_CODE', '123456')


class OtpBackend(BaseOtpBackend):

    def __init__(self):
        self.dummy_static = OTP_STATIC_CODE
        logging.debug(f"dummy_static={self.dummy_static}")

    def verify(self, username, password, otp) -> bool:
        return otp == self.dummy_static
