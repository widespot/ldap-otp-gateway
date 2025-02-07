import logging
import os

from .base_otp_backend import BaseOtpBackend


class OtpBackend(BaseOtpBackend):

    def __init__(self, dummy_static=None):
        self.dummy_static = dummy_static if dummy_static is not None else os.environ.get('OTP_STATIC_CODE', '123456')
        logging.info(f"dummy_static={self.dummy_static}")

    def verify(self, username, password, otp) -> (bool, (str or None)):
        return otp == self.dummy_static, None
