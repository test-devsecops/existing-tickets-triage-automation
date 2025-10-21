import requests
import time
import functools
import sys
import traceback

class ExceptionHandler:

    @staticmethod
    def _find_logger(self):
        """Dynamically find a logger-like attribute in self."""
        if not self:
            return None

        for attr_name in dir(self):
            if attr_name.startswith("__"):
                continue
            attr = getattr(self, attr_name)
            if callable(getattr(attr, "error", None)) and callable(getattr(attr, "info", None)):
                return attr
        return None

    @staticmethod
    def handle_exception(func=None, *, custom_message=None, reraise=False, logger=None, log_error=True):
        """
        Flexible decorator with optional custom message, logger injection, reraise support, and log_error toggle.
        Works for static/class/instance methods.
        """
        def decorator(inner_func):
            @functools.wraps(inner_func)
            def wrapper(*args, **kwargs):
                # Try to find logger from self, or use the injected one
                self_obj = args[0] if args else None
                log = ExceptionHandler._find_logger(self_obj) or logger

                try:
                    return inner_func(*args, **kwargs)
                except Exception as err:
                    exc_type, exc_value, exc_tb = sys.exc_info()
                    tb = traceback.extract_tb(exc_tb)
                    if tb:
                        last_frame = tb[-1]
                        filename = last_frame.filename
                        lineno = last_frame.lineno
                        funcname = last_frame.name
                    else:
                        filename = funcname = lineno = "Unknown"

                    err_type = type(err).__name__
                    msg = f"{err_type}: {err} | File: {filename} | Function: {funcname} | Line: {lineno}"
                    if custom_message:
                        msg = f"{custom_message} | {msg}"

                    if log_error:
                        if log:
                            log_func = log.warning if isinstance(err, ValueError) else log.error
                            log_func(msg)
                        else:
                            print(f"[LOG] {msg}")

                    if reraise:
                        raise
                return None
            return wrapper

        if callable(func):
            return decorator(func)
        return decorator

    @staticmethod
    def handle_exception_with_retries(func=None, *, retries=2, delay=1.5, custom_message=None, reraise=False, logger=None, log_error=True):
        """
        Flexible retry decorator with dynamic logger detection, injected logger support,
        custom messages, and re-raise option.

        Works for instance, class, and static methods.
        """
        def decorator(inner_func):
            @functools.wraps(inner_func)
            def wrapper(*args, **kwargs):
                self_obj = args[0] if args else None
                log = ExceptionHandler._find_logger(self_obj) or logger

                for attempt in range(1, retries + 1):
                    try:
                        return inner_func(*args, **kwargs)
                    except Exception as err:
                        # Extract traceback info
                        exc_type, exc_value, exc_tb = sys.exc_info()
                        tb = traceback.extract_tb(exc_tb)
                        if tb:
                            last_frame = tb[-1]
                            filename = last_frame.filename
                            lineno = last_frame.lineno
                            funcname = last_frame.name
                        else:
                            filename = funcname = lineno = "Unknown"

                        err_type = type(err).__name__
                        msg = (f"{err_type}: {err} | File: {filename} | Function: {funcname} | "
                            f"Line: {lineno} | Retry {attempt}/{retries}")
                        if custom_message:
                            msg = f"{custom_message} | {msg}"

                        # Log dynamically
                        if log_error:
                            if log:
                                log_func = log.warning if isinstance(err, ValueError) else log.error
                                log_func(msg)
                            else:
                                print(f"[LOG] {msg}")

                        # Wait or re-raise
                        if attempt < retries:
                            time.sleep(delay)
                        elif reraise:
                            raise

                return None
            return wrapper

        # Supports both decorator styles: @decorator and @decorator()
        if callable(func):
            return decorator(func)
        return decorator
