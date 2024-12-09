class BaseOtpBackend:
    def verify(self, username, password, otp) -> bool:
        raise NotImplementedError("Not implemented")
