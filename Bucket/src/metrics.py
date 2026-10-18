import logging
import os

from prometheus_client import CollectorRegistry, Gauge, push_to_gateway

from src.utils.models import ScanResult, Severity

logger = logging.getLogger(__name__)

# Grafana panels keep their metric names; the gauges are now derived from Finding.severity.
GAUGE_BY_SEVERITY = {
    Severity.HIGH: "danger",
    Severity.MEDIUM: "warning",
    Severity.LOW: "safe",
    Severity.INFO: "safe",
    Severity.UNKNOWN: "unknown",
}


def severity_counts(result: ScanResult) -> dict[str, int]:
    counts = {"danger": 0, "warning": 0, "safe": 0, "unknown": 0}
    for finding in result.findings:
        counts[GAUGE_BY_SEVERITY[finding.severity]] += 1
    return counts


def build_registry(result: ScanResult) -> CollectorRegistry:
    registry = CollectorRegistry()
    counts = severity_counts(result)

    Gauge("scanner_danger_findings", "Number of high severity findings", registry=registry).set(counts["danger"])
    Gauge("scanner_warning_findings", "Number of medium severity findings", registry=registry).set(counts["warning"])
    Gauge("scanner_safe_findings", "Number of low/info severity findings", registry=registry).set(counts["safe"])
    Gauge("scanner_unknown_findings", "Number of checks that could not be completed",
          registry=registry).set(counts["unknown"])
    Gauge("scanner_buckets_scanned", "Buckets scanned", registry=registry).set(len(result.buckets))
    Gauge("scanner_total_checks", "Total number of checks performed", registry=registry).set(len(result.findings))
    return registry


def send_metrics(result: ScanResult) -> None:
    registry = build_registry(result)
    counts = severity_counts(result)

    pushgateway_url = os.getenv("PUSHGATEWAY_URL", "http://pushgateway:9091")
    try:
        push_to_gateway(pushgateway_url, job="bucket_scanner", registry=registry)
        logger.info(f"Метрики отправлены в Pushgateway: {pushgateway_url}")
        logger.info(
            f"Статистика: DANGER={counts['danger']}, WARNING={counts['warning']}, SAFE={counts['safe']}, "
            f"UNKNOWN={counts['unknown']}, Checks={len(result.findings)}, Buckets={len(result.buckets)}"
        )
    except Exception as e:
        logger.error(f"Ошибка отправки метрик: {e}")
