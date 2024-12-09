from .base_otp_extractor import BaseOTPExtractor


class OtpExtractor(BaseOTPExtractor):
    def extract(self, request) -> [bytes, bytes]:
        if len(request.auth) < 6:
            raise Exception("Missing OTP credentials")

        password = request.auth[:-6]
        otp = request.auth[-6:]

        return [password, otp]
