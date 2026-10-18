from botocore.exceptions import ClientError
import logging

from src.utils.models import Finding, Severity

logger = logging.getLogger(__name__)


def except_function(
    e: ClientError,
    bucket_name: str,
    rule_id: str,
    not_configured_codes: list[str],
    missing_severity: Severity = Severity.LOW,
    missing_message: str = "Конфигурация не задана",
) -> Finding:
    error_code = e.response.get("Error", {}).get("Code", "")

    if error_code in not_configured_codes:
        logger.info(f"Бакет: {bucket_name}: {rule_id} - NO_CONFIGURATION")
        return Finding(rule_id, missing_severity, bucket_name, missing_message, {"error_code": error_code})

    logger.error(f"Бакет: {bucket_name}: {rule_id} - ERROR: {e}")
    return Finding(
        rule_id,
        Severity.UNKNOWN,
        bucket_name,
        f"Не удалось выполнить проверку: {error_code or 'ClientError'}",
        {"error_code": error_code, "error": str(e)},
    )
