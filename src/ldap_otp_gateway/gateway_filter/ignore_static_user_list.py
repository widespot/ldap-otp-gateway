import logging
import os
import json

from .base_gateway_filter import BaseGatewayFilter


class GatewayFilter(BaseGatewayFilter):

    def __init__(self, ignore_list: list[str] = None):
        self.ignore_list = ignore_list if ignore_list is not None else json.loads(os.getenv('GATEWAY_FILTER_IGNORE_USERS', '[]'))
        logging.info(f"Gateway filter ignore static list of users: {self.ignore_list}")

    def ignore(self, request) -> bool:
        username = request.dn.decode()
        return username in self.ignore_list
