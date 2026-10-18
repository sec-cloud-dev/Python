import json
import logging
import os
from typing import Any

import psycopg2
from psycopg2.extras import Json

from src.utils.models import Finding, ScanResult

logger = logging.getLogger(__name__)

# rule_id -> TEXT column holding that finding's severity
SEVERITY_COLUMNS = {
    "bucket.policy": "policy",
    "bucket.versioning": "versioning",
    "bucket.encryption": "encryption",
    "bucket.cors": "cors",
    "bucket.lifecycle": "lifecycle",
    "bucket.acl": "acl",
    "bucket.mfa_delete": "mfa",
    "bucket.object_lock": "object_lock",
    "bucket.logging": "logging",
    "bucket.replication": "replication",
}

# rule_id -> JSONB column holding the whole finding. iam.* are folder-level and repeated on every bucket row.
FINDING_COLUMNS = {
    "iam.vm_sa_access": "bindings",
    "iam.sa_roles": "roles",
    "iam.static_keys": "stat_key",
    "functions.trigger_sa": "function",
    "cdn.origin": "cdn",
}


def _json(value: Any) -> Json:
    return Json(value, dumps=lambda obj: json.dumps(obj, default=str))


def _row(bucket: str, findings: list[Finding], result: ScanResult) -> tuple[Any, ...]:
    by_rule = {f.rule_id: f for f in findings + result.folder_findings}
    severities = [by_rule[r].severity.value if r in by_rule else None for r in SEVERITY_COLUMNS]
    details = [_json(by_rule[r].to_dict()) if r in by_rule else None for r in FINDING_COLUMNS]
    full_report = {
        "bucket": bucket,
        "findings": [f.to_dict() for f in findings],
        "folder_findings": [f.to_dict() for f in result.folder_findings],
    }
    return (bucket, *severities, *details, _json(full_report))


def bd_result(result: ScanResult) -> None:
    """Persist a scan atomically and always release database resources."""
    logger.info("Начинаем подключаться к БД")
    with psycopg2.connect(
        host=os.getenv("DB_HOST"),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        connect_timeout=5,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_result_bucket(
                    id BIGSERIAL PRIMARY KEY,
                    scan_date TIMESTAMPTZ DEFAULT NOW(),
                    bucket_name TEXT NOT NULL,
                    policy TEXT,
                    versioning TEXT,
                    encryption TEXT,
                    cors TEXT,
                    lifecycle TEXT,
                    acl TEXT,
                    mfa TEXT,
                    object_lock TEXT,
                    logging TEXT,
                    replication TEXT,
                    bindings JSONB,
                    roles JSONB,
                    stat_key JSONB,
                    function JSONB,
                    cdn JSONB,
                    full_report JSONB NOT NULL
                )
            """)

            for bucket, findings in result.buckets.items():
                cur.execute(
                    """
                    INSERT INTO scan_result_bucket(
                        bucket_name, policy, versioning, encryption, cors,
                        lifecycle, acl, mfa, object_lock, logging, replication,
                        bindings, roles, stat_key, function, cdn, full_report
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    _row(bucket, findings, result),
                )
    logger.info("Сохранено %s записей в БД", len(result.buckets))


__all__ = ["bd_result"]
