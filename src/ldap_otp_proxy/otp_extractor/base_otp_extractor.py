class BaseOTPExtractor(object):
    def extract(self, request) -> [str, str, str]:
        raise NotImplementedError("Please implement")
