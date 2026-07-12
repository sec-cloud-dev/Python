from botocore.exceptions import ClientError
import logging
from typing import Any

logger = logging.getLogger(__name__)


def except_function(
    e: ClientError, bucket_name: str, operation_name: str, error_codes: list[str]
) -> str | dict[str, Any]:
    error_code = e.response["Error"]["Code"]

    if error_code in error_codes:
        logger.info(f"Бакет: {bucket_name}: {operation_name} - NO_CONFIGURATION")
        return "NO_CONFIGURATION"
    else:
        logger.error(f"Бакет: {bucket_name}: {operation_name} - ERROR: {e}")
        return {"ERROR": str(e)}
