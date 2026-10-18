import logging
from typing import Any, Callable

from src.checks.bucket_checks import (
    bucket_acl,
    bucket_cors,
    bucket_encrriptyon,
    bucket_lifecycle,
    bucket_logging,
    bucket_mfa,
    bucket_object,
    bucket_policy,
    bucket_replication,
    bucket_versioning,
)
from src.checks.cdn_checks import bucket_cdn_checkout
from src.checks.function_checks import bucket_triggers_checkout
from src.checks.sa_checks import check_all_sa_bucket, checks_sa_stat_key
from src.checks.vm_checks import checks_vm_sa_bucket_access
from src.inventory import CloudInventory
from src.utils.models import FOLDER_SCOPE, Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

# S3 API checks: check(s3_client, bucket_name)
BUCKET_CHECKS: tuple[tuple[str, Callable[[Any, str], Finding]], ...] = (
    ("bucket.policy", bucket_policy),
    ("bucket.versioning", bucket_versioning),
    ("bucket.encryption", bucket_encrriptyon),
    ("bucket.cors", bucket_cors),
    ("bucket.lifecycle", bucket_lifecycle),
    ("bucket.acl", bucket_acl),
    ("bucket.mfa_delete", bucket_mfa),
    ("bucket.object_lock", bucket_object),
    ("bucket.logging", bucket_logging),
    ("bucket.replication", bucket_replication),
)

# Bucket-specific checks over the folder inventory: check(inventory, bucket_name)
INVENTORY_BUCKET_CHECKS: tuple[tuple[str, Callable[[CloudInventory, str], Finding]], ...] = (
    ("functions.trigger_sa", bucket_triggers_checkout),
    ("cdn.origin", bucket_cdn_checkout),
)

# Folder-level IAM checks, evaluated once per folder: check(inventory)
FOLDER_CHECKS: tuple[tuple[str, Callable[[CloudInventory], Finding]], ...] = (
    ("iam.vm_sa_access", checks_vm_sa_bucket_access),
    ("iam.sa_roles", check_all_sa_bucket),
    ("iam.static_keys", checks_sa_stat_key),
)


def _run_check(rule_id: str, bucket: str, check: Callable[..., Finding], *args: Any) -> Finding:
    """A crashed check is reported as UNKNOWN, never as SAFE."""
    try:
        return check(*args)
    except Exception as exc:
        logger.exception("Проверка %s для %s завершилась ошибкой", rule_id, bucket)
        return Finding(rule_id, Severity.UNKNOWN, bucket, f"Проверка не выполнена: {exc}",
                       {"error": type(exc).__name__})


def scan(s3_client: Any, inventory: CloudInventory, bucket_names: list[str]) -> ScanResult:
    folder_findings = [_run_check(rule_id, FOLDER_SCOPE, check, inventory) for rule_id, check in FOLDER_CHECKS]

    buckets: dict[str, list[Finding]] = {}
    for name in bucket_names:
        logger.info("Сканирование бакета: %s", name)
        findings = [_run_check(rule_id, name, check, s3_client, name) for rule_id, check in BUCKET_CHECKS]
        findings += [_run_check(rule_id, name, check, inventory, name) for rule_id, check in INVENTORY_BUCKET_CHECKS]
        buckets[name] = findings

    logger.info("Сканирование завершено. Проверено бакетов: %s", len(buckets))
    return ScanResult(folder_id=inventory.folder_id, buckets=buckets, folder_findings=folder_findings)


def live_scan(folder_id: str, cloud_id: str) -> ScanResult:
    """Scan a Yandex Cloud folder. Folder inventory (IAM, VMs, SAs, keys) is loaded once, not per bucket."""
    from src.clients.boto3_client import boto3_logging
    from src.clients.yandex_client import bucket_get
    from src.inventory import load_inventory

    logger.info("Начало сканирование бакетов")
    bucket_names = [b["name"] for b in bucket_get(folder_id) if b.get("name")]
    inventory = load_inventory(folder_id, cloud_id)
    return scan(boto3_logging(), inventory, bucket_names)
