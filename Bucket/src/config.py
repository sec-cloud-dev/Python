import os
from dotenv import load_dotenv
from botocore.config import Config

load_dotenv()

token = os.getenv("TOKEN")
folder_id = os.getenv("FOLDER_ID")
cloud_id = os.getenv("CLOUD_ID")
key = os.getenv("key_id")
secret_key = os.getenv("secret_key")

config = Config(retries={"max_attempts": 3, "mode": "adaptive"})

DANGEROUS_ROLES = {"storage.admin", "storage.editor", "admin", "editor"}

SAFE_ROLES = {"storage.viewer", "storage.configViewer", "viewer"}