from checkmarx_utility.cx_config_utility import Config
from checkmarx_utility.cx_api_endpoints import CxApiEndpoints
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
        raw_token = None

        if response and response.get("success"):
            data = response.get("data", {})
            raw_token = data.get("access_token")
            if raw_token:
                self._cached_token = raw_token
                self._expiry = time.time() + data.get("expires_in", 1800) - 10
                if self.logger:
                    self.logger.info("Generated new token")
                else:
                    print("Generated new token")
        else:
            error_details = response.get("error") if response else "No response"
            if self.logger:
                self.logger.error(f"Failed to fetch token: {error_details}")
            else:
                print(f"Failed to fetch token: {error_details}")

        return raw_token

    def get_valid_token(self):
        if not self._cached_token or time.time() >= self._expiry:
            if self.logger:
                self.logger.info("Token expired/missing. Renewing...")
            else:
                print("Token expired/missing. Renewing...")
            return self.fetch_new_token()
        return self._cached_token
