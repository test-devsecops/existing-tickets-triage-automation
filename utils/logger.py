import os
import logging
from datetime import datetime

class Logger:
    SUCCESS_LEVEL = 25
    SKIPPED_LEVEL = 35

    def __init__(self, filename=None, log_dir="logs", create_log_file=True):
        """
        Args:
            filename (str or None): Base name for the log file (without extension). If None, uses 'app' as default.
            log_dir (str): Directory for log files.
            create_log_file (bool): Whether to create a log file. If False, only console logging is used.
        """
        self.create_log_file = create_log_file
        self.log_dir = log_dir

        # Determine logger name and log file name
        if filename is None:
            self.filename = "app"
        else:
            self.filename = filename

        self.log_file = None

        # Set up the logger
        logger_name = self.filename if self.filename else "default"
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG)

        # Register custom log levels
        logging.addLevelName(self.SUCCESS_LEVEL, "SUCCESS")
        logging.addLevelName(self.SKIPPED_LEVEL, "SKIPPED")

        # Avoid adding multiple handlers if logger already exists
        if not self.logger.handlers:
            formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', 
                                        datefmt='%Y-%m-%d %H:%M:%S')

            # File handler (optional)
            if self.create_log_file:
                # Create logs directory if it doesn't exist
                os.makedirs(self.log_dir, exist_ok=True)
                # Generate timestamped filename
                timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
                self.log_file = os.path.join(self.log_dir, f"{self.filename}_{timestamp}.log")
                file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)

            # Console handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

    def info(self, message):
        self.logger.info(message)

    def error(self, message):
        self.logger.error(message, exc_info=True)

    def warning(self, message):
        self.logger.warning(message)

    def debug(self, message):
        self.logger.debug(message)

    def success(self, message):
        self.logger.log(self.SUCCESS_LEVEL, message)

    def skipped(self, message):
        self.logger.log(self.SKIPPED_LEVEL, message)

    def get_log_file_path(self):
        """Return the full path of the generated log file, or None if not created."""
        return self.log_file
