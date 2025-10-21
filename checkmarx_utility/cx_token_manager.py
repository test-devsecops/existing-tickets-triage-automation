from checkmarx_utility.cx_config_utility import Config
from checkmarx_utility.cx_api_endpoints import CxApiEndpoints

from utils.exception_handler import ExceptionHandler
from utils.http_utility import HttpRequests

import time
from urllib.parse import urlencode


class AccessTokenManager:
    def __init__(self, logger=None):
        self.httpRequest = HttpRequests()
        self.apiEndpoints = CxApiEndpoints()
        self.config = Config() #"config.env"
        self.logger = logger
        self._expiry = 0
        self._cached_token = None

        self.refresh_token, self.tenant_name, self.tenant_iam_url, self.tenant_url = self.config.get_config()

    @ExceptionHandler.handle_exception
    def fetch_new_token(self):

        endpoint = self.apiEndpoints.openid_token(self.tenant_name)
        url = f"https://{self.tenant_iam_url}{endpoint}"
        headers = {
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            "grant_type": "refresh_token",
            "client_id": "ast-app",
            "refresh_token": self.refresh_token
        }

        encoded_data = urlencode(data)
        response = self.httpRequest.post_api_request(url, headers, encoded_data)
        raw_token = response.get("access_token")

        if raw_token:
            self._cached_token = raw_token
            self._expiry = time.time() + response.get("expires_in", 1800) - 10
            if self.logger:
                self.logger.info("Generated new token")
            else:
                print("Generated new token")

        return raw_token

    def get_valid_token(self):
        if not self._cached_token or time.time() >= self._expiry:
            if self.logger:
                self.logger.info("Token expired/missing. Renewing...")
            else:
                print("Token expired/missing. Renewing...")
            return self.fetch_new_token()
        return self._cached_token
