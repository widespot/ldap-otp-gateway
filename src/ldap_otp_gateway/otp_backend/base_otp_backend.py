class BaseOtpBackend:
    def verify(self, username, password, otp) -> (bool, (str or None)):
        raise NotImplementedError("Not implemented")
