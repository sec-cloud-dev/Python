import logging
import psycopg2
from psycopg2.extras import Json
import os
from typing import Any

logger = logging.getLogger(__name__)


def bd_result(reports: list[dict[str, Any]]) -> None:
    try:
        logging.info("Начинаем подключаться к БД")
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST"),
            database=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            connect_timeout=5,
        )

        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_result_bucket(
                id SERIAL PRIMARY KEY,
                scan_date TIMESTAMP DEFAULT NOW(),
                bucket_name TEXT,
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
                full_report JSONB
            )
        """)

        for report in reports:
            cur.execute(
                """
                INSERT INTO scan_result_bucket(
                    bucket_name, policy, versioning, encryption, cors,
                    lifecycle, acl, mfa, object_lock, logging, replication, 
                    bindings, roles, stat_key, function, cdn, full_report
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
                (
                    report.get("Bucket_Name"),
                    str(report.get("Policy")),
                    str(report.get("Versioning")),
                    str(report.get("Encryption")),
                    str(report.get("Cors")),
                    str(report.get("Lifecycle")),
                    str(report.get("Acl")),
                    str(report.get("Mfa")),
                    str(report.get("ObjectLock")),
                    str(report.get("Logging")),
                    str(report.get("Replication")),
                    Json(report.get("Bindings")),
                    Json(report.get("All_sa")),
                    Json(report.get("Stat_key_sa")),
                    Json(report.get("Function_sa")),
                    Json(report.get("Cdn_storage")),
                    Json(report),
                ),
            )

        conn.commit()
        cur.close()
        conn.close()
        logger.info(f"Сохранено {len(reports)} записей в БД")

    except Exception as e:
        logger.error(f"Ошибка сохранения в БД: {e}")
