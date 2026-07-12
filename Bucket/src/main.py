import logging
import os
from typing import Any
from src.config import folder_id, cloud_id
from src.clients.boto3_client import boto3_logging
from src.clients.yandex_client import bucket_get
from src.checks.bucket_checks import (
    bucket_policy,
    bucket_versioning,
    bucket_encrriptyon,
    bucket_cors,
    bucket_lifecycle,
    bucket_acl,
    bucket_mfa,
    bucket_object,
    bucket_logging,
    bucket_replication,
)
from src.checks.vm_checks import checks_vm_sa_bucket_access
from src.checks.sa_checks import check_all_sa_bucket, checks_sa_stat_key
from src.checks.function_checks import bucket_triggers_checkout
from src.checks.cdn_checks import bucket_cdn_checkout
from src.clients.db_client import bd_result
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway
import sys

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", stream=sys.stdout, force=True
)
logger = logging.getLogger(__name__)


def send_metrics(reports: list[dict[str, Any]]):
    registry = CollectorRegistry()

    danger = Gauge("scanner_danger_findings", "Number of DANGER findings", registry=registry)
    warning = Gauge("scanner_warning_findings", "Number of WARNING findings", registry=registry)
    safe = Gauge("scanner_safe_findings", "Number of SAFE findings", registry=registry)
    scanned = Gauge("scanner_buckets_scanned", "Buckets scanned", registry=registry)
    total_checks = Gauge("scanner_total_checks", "Total number of checks performed", registry=registry)

    danger_count = 0
    warning_count = 0
    safe_count = 0
    checks_count = 0

    for report in reports:
        bucket_checks = [
            ("Policy", report.get("Policy")),
            ("Versioning", report.get("Versioning")),
            ("Encryption", report.get("Encryption")),
            ("Cors", report.get("Cors")),
            ("Lifecycle", report.get("Lifecycle")),
            ("Acl", report.get("Acl")),
            ("Mfa", report.get("Mfa")),
            ("ObjectLock", report.get("ObjectLock")),
            ("Logging", report.get("Logging")),
            ("Replication", report.get("Replication")),
        ]
        for check_name, status in bucket_checks:
            checks_count += 1
            if status == "DANGER":
                danger_count += 1
            elif status == "WARNING":
                warning_count += 1
            elif status in ("SAFE", "NO_CONFIGURATION"):
                safe_count += 1

        bindings = report.get("Bindings")
        if isinstance(bindings, dict):
            checks_count += 1
            status = bindings.get("status")
            if status == "DANGER":
                danger_count += 1
            elif status == "WARNING":
                warning_count += 1
            elif status == "SAFE":
                safe_count += 1

        all_sa = report.get("All_sa")
        if isinstance(all_sa, dict):
            checks_count += 1
            status = all_sa.get("status")
            if status == "DANGER":
                danger_count += 1
            elif status == "WARNING":
                warning_count += 1
            elif status == "SAFE":
                safe_count += 1

        stat_key = report.get("Stat_key_sa")
        if isinstance(stat_key, dict):
            checks_count += 1
            status = stat_key.get("status")
            if status == "DANGER":
                danger_count += 1
            elif status == "WARNING":
                warning_count += 1
            elif status == "SAFE":
                safe_count += 1

        function_sa = report.get("Function_sa")
        if isinstance(function_sa, dict):
            checks_count += 1
            status = function_sa.get("Risk")
            if status == "DANGER":
                danger_count += 1
            elif status == "WARNING":
                warning_count += 1
            elif status == "SAFE":
                safe_count += 1

        cdn = report.get("Cdn_storage")
        if isinstance(cdn, dict):
            checks_count += 1
            status = cdn.get("risk")
            if status == "DANGER":
                danger_count += 1
            elif status == "WARNING":
                warning_count += 1
            elif status == "SAFE":
                safe_count += 1

    scanned.set(len(reports))
    total_checks.set(checks_count)
    danger.set(danger_count)
    warning.set(warning_count)
    safe.set(safe_count)

    pushgateway_url = os.getenv("PUSHGATEWAY_URL", "http://pushgateway:9091")
    try:
        push_to_gateway(pushgateway_url, job="bucket_scanner", registry=registry)
        logger.info(f"Метрики отправлены в Pushgateway: {pushgateway_url}")
        logger.info(
            f"Статистика: DANGER={danger_count}, WARNING={warning_count}, SAFE={safe_count}, Checks={checks_count}, Buckets={len(reports)}"
        )
    except Exception as e:
        logger.error(f"Ошибка отправки метрик: {e}")


def bucket_checkout() -> list[dict[str, Any]]:
    logger.info("Начало сканирование бакетов")
    clients = boto3_logging()
    reports = []
    buckets = bucket_get(folder_id)

    for b in buckets:
        name = b.get("name")
        all_reports = {
            "Bucket_Name": name,
            "Policy": bucket_policy(clients, name),
            "Versioning": bucket_versioning(clients, name),
            "Encryption": bucket_encrriptyon(clients, name),
            "Cors": bucket_cors(clients, name),
            "Lifecycle": bucket_lifecycle(clients, name),
            "Acl": bucket_acl(clients, name),
            "Mfa": bucket_mfa(clients, name),
            "ObjectLock": bucket_object(clients, name),
            "Logging": bucket_logging(clients, name),
            "Replication": bucket_replication(clients, name),
            "Bindings": checks_vm_sa_bucket_access(folder_id, cloud_id, name),
            "All_sa": check_all_sa_bucket(folder_id, cloud_id, name),
            "Stat_key_sa": checks_sa_stat_key(folder_id),
            "Function_sa": bucket_triggers_checkout(folder_id, cloud_id, name),
            "Cdn_storage": bucket_cdn_checkout(folder_id, name),
        }
        reports.append(all_reports)

    logger.info(f"Сканирование завершено. Проверено бакетов: {len(reports)}")
    return reports


def main():
    report = bucket_checkout()
    if report:
        bd_result(report)
        send_metrics(report)
        logger.info("")
        logger.info("==================== ДОСТУПНЫЕ СЕРВИСЫ ====================")
        logger.info("Pushgateway (метрики):       http://localhost:9091/metrics")
        logger.info("Prometheus (запросы):        http://localhost:9090")
        logger.info("Grafana (дашборды):          http://localhost:3000 (admin/admin)")
        logger.info("===========================================================")
        logger.info("")


if __name__ == "__main__":
    main()
