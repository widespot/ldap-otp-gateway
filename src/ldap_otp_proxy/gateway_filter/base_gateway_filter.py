class BaseGatewayFilter():
    def ignore(self, request) -> bool:
        return False
