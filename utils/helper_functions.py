from utils.logger import Logger
from utils.exception_handler import ExceptionHandler
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
from urllib.parse import urlparse, parse_qs
from datetime import datetime

import string
import re
import math

class HelperFunctions:
    logger = Logger(create_log_file=False)
    
    @staticmethod
    def get_today_date_yyyymmdd():
        return datetime.today().strftime('%Y%m%d')

    @staticmethod
    def get_lbu_name_simple(app_name):
        """
        Extracts the LBU name directly after 'pru-' in the given project_name.
        Does not validate against any JSON list.
        """
        match = re.search(r'^pru-([\w]+)', app_name, re.IGNORECASE)
        if match:
            return match.group(1).upper()
        
        return "Pru"

    @staticmethod
    def is_readable(text):
        # Check if all characters in a string are readable (printable)
        if all(char in string.printable for char in text):
            return True
        return False

    @staticmethod
    def is_missing_or_unreadable(value):
        """
        Returns True if the value is NaN, None, empty, or not readable as a string.
        """
        is_nan = isinstance(value, float) and math.isnan(value)
        if is_nan or not value or not HelperFunctions.is_readable(str(value)):
            return True
        return False
    
    @staticmethod
    def get_nested(data, keys, default=None):
        """
        Safely access nested dictionary keys.
        
        :param data: The dictionary to traverse.
        :param keys: A list of keys representing the path.
        :param default: Value to return if any key is missing.
        :return: The value at the nested key or default.
        """
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key, default)
            else:
                return default
        return data
    
    @staticmethod
    def shorten_strings_middle(s, front=4, back=3):
        return s if len(s) <= (front + back) else s[:front] + "..." + s[-back:]
    
    @staticmethod
    @ExceptionHandler.handle_exception_with_retries(logger=logger)
    def get_future_date(time_text: str) -> str:
        # Get current UTC datetime
        now = datetime.utcnow()

        # Normalize input text
        time_text = time_text.strip().lower()

        # Extract numeric value
        parts = time_text.split()
        if len(parts) < 2:
            raise ValueError("Input must include both number and unit (e.g., '15 days')")

        try:
            number = int(parts[0])
        except ValueError:
            raise ValueError("The first part must be a number (e.g., '15 days')")

        unit = parts[1]
        
        # Compute based on unit
        if "day" in unit:
            future_date = now + timedelta(days=number)
        elif "week" in unit:
            future_date = now + timedelta(weeks=number)
        elif "month" in unit:
            future_date = now + relativedelta(months=number)
        else:
            raise ValueError("Unsupported time unit. Use 'days', 'weeks', or 'months'.")

        # Return ISO 8601 format with milliseconds and 'Z'
        return future_date.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    
    @staticmethod
    def set_package_and_version(package_version: str) -> tuple[str, str]:
        """
        Splits a package string into name and version for SCA.
        Example: 'multer 1.4.5-lts.2' -> ('multer', '1.4.5-lts.2')
        """
        try:
            name, version = package_version.rsplit(" ", 1)
            return name, version
        except Exception as e:
            return None, None

    
    @staticmethod
    def extract_ids_from_result_url(b7_value):
        """
        Extracts the full project_id and scan_id from the value of cell B7.
        The value may be a URL containing two UUIDs (project ID and scan ID), or a string with two UUIDs/hashes.

        Example B7 value: 'https://.../results/984ee41e-ec26-48ef-bc44-a4f0493089e5/a4f0493089e5-ec26-48ef-bc44-984ee41e6511'
        Returns: {'project_id': '984ee41e-ec26-48ef-bc44-a4f0493089e5', 'scan_id': 'a4f0493089e5-ec26-48ef-bc44-984ee41e6511'}
        """
        if not isinstance(b7_value, str):
            return {"project_id": None, "scan_id": None}

        # Match full UUIDs (with hyphens)
        uuid_regex = r'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}'
        matches = re.findall(uuid_regex, b7_value)
        if len(matches) >= 2:
            return {"project_id": matches[0], "scan_id": matches[1]}
        else:
            # Fallback: split by whitespace and take first two parts
            parts = b7_value.strip().split()
            if len(parts) >= 2:
                return {"project_id": parts[0], "scan_id": parts[1]}
            else:
                return {"project_id": None, "scan_id": None}
