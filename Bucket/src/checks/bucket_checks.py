import json
from typing import Any
from botocore.exceptions import ClientError
from src.utils.error_utils import except_function
import logging

logger = logging.getLogger(__name__)


def bucket_policy(client: Any, name: str) -> str | dict[str, Any]:
    logger.info(f"Проверка Policy для бакета: {name}")
    try:
        response = client.get_bucket_policy(Bucket=name)
        jsons = json.loads(response["Policy"])
        state = jsons.get("Statement", [])

        flags = False

        for i in state:
            effect = i.get("Effect", "")
            pris = i.get("Principal", "")

            if effect == "Allow" and (pris == "*" or pris == {"AWS": "*"}):
                flags = True
                break
        if flags:
            logger.warning(f"Бакет: {name}: Policy - DANGER")
            return "DANGER"
        logger.info(f"Бакет: {name}: Policy - SAFE")
        return "SAFE"
    except ClientError as e:
        return except_function(e, name, "bucket_policy", ["NoSuchBucketPolicy"])


def bucket_versioning(client: Any, name: str) -> str | dict[str, Any]:
    logger.info(f"Проверка versioning для бакета: {name}")
    try:
        response = client.get_bucket_versioning(Bucket=name)
        status = response.get("Status", "Suspended")
        logger.info(f"Бакет: {name}: Versioning - status: {status}")
        return {"Status": status}
    except ClientError as e:
        return except_function(e, name, "bucket_versioning", [])


def bucket_encrriptyon(client: Any, name: str) -> str | dict[str, Any]:
    logger.info(f"Проверка encriptyon для бакета: {name}")
    try:
        response = client.get_bucket_encryption(Bucket=name)
        logger.info(f"Бакет: {name}: Encryption - {response}")
        return response
    except ClientError as e:
        return except_function(e, name, "bucket_encrriptyon", ["ServerSideEncryptionConfigurationNotFoundError"])


def bucket_cors(client: Any, name: str) -> str | dict[str, Any]:
    logger.info(f"Проверка cors для бакета: {name}")
    try:
        response = client.get_bucket_cors(Bucket=name)
        rule = response.get("CORSRules", [])

        flags = False

        for i in rule:
            allow = i.get("AllowedOrigins", [])

            if "*" in allow:
                flags = True
                break
        if flags:
            logger.warning(f"Бакет: {name}: Cors - DANGER")
            return "DANGER"
        logger.info(f"Бакет: {name}: Cors - SAFE")
        return "SAFE"
    except ClientError as e:
        return except_function(e, name, "bucket_cors", ["NoSuchCORSConfiguration"])


def bucket_lifecycle(client: Any, name: str) -> str | dict[str, Any]:
    logger.info(f"Проверка lifecycle для бакета: {name}")
    try:
        response = client.get_bucket_lifecycle_configuration(Bucket=name)
        logger.info(f"Бакет: {name}: lifecycle - {response}")
        return response
    except ClientError as e:
        return except_function(e, name, "bucket_lifecycle", ["NoSuchLifecycleConfiguration"])


def bucket_acl(client: Any, name: str) -> str | dict[str, Any]:
    logger.info(f"Проверка acl для бакета: {name}")
    try:
        dangerous_uri = {
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
        }
        response = client.get_bucket_acl(Bucket=name)
        grant = response.get("Grants", [])

        reports = []

        for i in grant:
            grantee = i.get("Grantee", {})
            if grantee.get("Type", "") == "Group":
                uri = grantee.get("URI", "")
                if uri in dangerous_uri:
                    reports.append({"URI": uri, "Permission": i.get("Permission", "")})
        if reports:
            logger.warning(f"Бакет: {name}: Acl - DANGER")
            return {"DANGER": reports}
        logger.info(f"Бакет: {name}: Acl - SAFE")
        return "SAFE"
    except ClientError as e:
        return except_function(e, name, "bucket_acl", ["NoSuchBucketAcl"])


def bucket_mfa(client: Any, name: str) -> str | dict[str, Any]:
    logger.info(f"Проверка mfa для бакета: {name}")
    try:
        response = client.get_bucket_versioning(Bucket=name)
        mfa = response.get("MFADelete", "")

        if not mfa:
            return "NO_CONFIGURATION"
        if mfa == "Disabled":
            logger.warning(f"Бакет: {name}: Mfa - DANGER")
            return "DANGER"
        logger.info(f"Бакет: {name}: Mfa - SAFE")
        return "SAFE"
    except ClientError as e:
        return except_function(e, name, "bucket_mfa", [])


def bucket_object(client: Any, name: str) -> str | dict[str, Any]:
    logger.info(f"Проверка object для бакета: {name}")
    try:
        response = client.get_object_lock_configuration(Bucket=name)
        objects = response.get("ObjectLockConfiguration", {}).get("Rule", {}).get("DefaultRetention", {})

        mode = objects.get("Mode", "")
        days = objects.get("Days", "")
        info = {"Mode": mode, "Days": days}

        if mode == "GOVERNANCE":
            logger.warning(f"Бакет: {name}: Object - DANGER")
            return {"DANGER": info}
        logger.info(f"Бакет: {name}: Object - SAFE")
        return {"SAFE": info}
    except ClientError as e:
        return except_function(e, name, "bucket_object", ["ObjectLockConfigurationNotFoundError"])


def bucket_logging(client: Any, name: str) -> str | dict[str, Any]:
    logger.info(f"Проверка logging для бакета: {name}")
    try:
        response = client.get_bucket_logging(Bucket=name)
        log = response.get("LoggingEnabled", {})

        if not log:
            logger.warning(f"Бакет: {name}: Logging - NO_CONFIGURATION")
            return "NO_CONFIGURATION"
        logger.info(f"Бакет: {name}: Logging - SAFE")
        return "SAFE"
    except ClientError as e:
        return except_function(e, name, "bucket_logging", [])


def bucket_replication(clients: Any, name: str) -> str | dict[str, Any]:
    logger.info(f"Проверка replication для бакета: {name}")
    try:
        response = clients.get_bucket_replication(Bucket=name)
        replication = response.get("ReplicationConfiguration", {}).get("Rules", [])

        if not replication:
            logger.warning(f"Бакет: {name}: Replication - NO_CONFIGURATION")
            return "NO_CONFIGURATION"

        report = []

        for i in replication:
            statis = i.get("Status", "")
            ids = i.get("ID", "")

            if statis == "Disabled":
                report.append({"Status": statis, "Id": ids})
        if report:
            logger.warning(f"Бакет: {name}: Replication - DANGER")
            return {"DANGER": report}
        logger.info(f"Бакет: {name}: Replication - SAFE")
        return "SAFE"
    except ClientError as e:
        return except_function(e, name, "bucket_replication", ["ReplicationConfigurationNotFoundError"])
