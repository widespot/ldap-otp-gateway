class BaseOtp:
    def verify(self, username, password, otp) -> bool:
        raise NotImplementedError("Not implemented")
