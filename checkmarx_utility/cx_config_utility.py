import os
import sys
from dotenv import load_dotenv
from pathlib import Path

class Config:

    def __init__(self):
        """Initialize and load configuration from environment variables."""

        # Load the .env file from the same directory as the script. Uncomment this when running the scripts on your local machine
        env_path = Path(__file__).resolve().parent / '.env'
        load_dotenv(dotenv_path=env_path)

        self.token = os.getenv('CX_TOKEN')
        self.tenant_name = os.getenv('CX_TENANT_NAME')
        self.tenant_iam_url = os.getenv('CX_TENANT_IAM_URL')
        self.tenant_url = os.getenv('CX_TENANT_URL')

        missing = [var for var in ['CX_TOKEN', 'CX_TENANT_NAME', 'CX_TENANT_IAM_URL', 'CX_TENANT_URL'] if os.getenv(var) is None]
        if missing:
            print(f"Error: Missing required environment variables: {', '.join(missing)}")
            sys.exit(1)

    def get_config(self):
        """Return the loaded configuration values."""
        return self.token, self.tenant_name, self.tenant_iam_url, self.tenant_url