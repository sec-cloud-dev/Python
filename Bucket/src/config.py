import os

from botocore.config import Config
from dotenv import load_dotenv

load_dotenv()

token = os.getenv("TOKEN")
folder_id = os.getenv("FOLDER_ID")
cloud_id = os.getenv("CLOUD_ID")
key = os.getenv("key_id")
secret_key = os.getenv("secret_key")

config = Config(retries={"max_attempts": 3, "mode": "adaptive"})

DANGEROUS_ROLES = {"storage.admin", "storage.editor", "admin", "editor"}
SAFE_ROLES = {"storage.viewer", "storage.configViewer", "viewer"}


def validate_configuration() -> None:
    """Validate required non-secret identifiers and credential presence."""
    required = {
        "TOKEN": token,
        "FOLDER_ID": folder_id,
        "CLOUD_ID": cloud_id,
        "key_id": key,
        "secret_key": secret_key,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise ValueError(f"Не заданы обязательные переменные окружения: {', '.join(missing)}")


__all__ = [
    "DANGEROUS_ROLES", "SAFE_ROLES", "cloud_id", "config", "folder_id", "key", "secret_key",
    "token", "validate_configuration",
]
