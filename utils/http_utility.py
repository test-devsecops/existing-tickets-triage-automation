import requests
from utils.exception_handler import ExceptionHandler

class HttpRequests:
    def __init__(self, logger=None):
        self.logger = logger
    
    def _handle_response(self, response, valid_status_codes, method_name):
        if self.logger:
            self.logger.info(f"{method_name} {response.url} - Status Code: {response.status_code}")

        if response.status_code in valid_status_codes:
            try:
                data = response.json() if response.content and response.content.strip() else None
            except ValueError:
                data = response.text
            return {
                "success": True,
                "status_code": response.status_code,
                "data": data
            }
        else:
            try:
                error_details = response.json()
            except Exception:
                error_details = response.text.strip() or "Unknown error"
            # return {
            #     "success": False,
            #     "status_code": response.status_code,
            #     "error": error_details
            # }

            raise Exception(f"{method_name} {response.status_code} Error: {error_details}")

    @ExceptionHandler.handle_exception(logger=lambda self: self.logger)
    def post_api_request(self, url, headers=None, data=None, params=None, json=None):
        response = requests.post(url, headers=headers, data=data, params=params, json=json, timeout=120)
        return self._handle_response(response, [200, 201], "POST")

    @ExceptionHandler.handle_exception(logger=lambda self: self.logger)
    def get_api_request(self, url, headers=None, data=None, params=None, json=None):
        response = requests.get(url, headers=headers, data=data, params=params, json=json)
        return self._handle_response(response, [200, 201], "GET")

    @ExceptionHandler.handle_exception(logger=lambda self: self.logger)
    def patch_api_request(self, url, headers=None, data=None, params=None, json=None):
        response = requests.patch(url, headers=headers, data=data, params=params, json=json)
        return self._handle_response(response, [200, 201], "PATCH")

    @ExceptionHandler.handle_exception(logger=lambda self: self.logger)
    def delete_api_request(self, url, headers=None, data=None, params=None, json=None):
        response = requests.delete(url, headers=headers, data=data, params=params, json=json, timeout=360)
        return self._handle_response(response, [200, 204], "DELETE")
    
    @ExceptionHandler.handle_exception(logger=lambda self: self.logger)
    def put_api_request(self, url, headers=None, data=None, params=None, json=None):
        response = requests.put(url, headers=headers, data=data, params=params, json=json, timeout=120)
        return self._handle_response(response, [200, 204], "PUT")
