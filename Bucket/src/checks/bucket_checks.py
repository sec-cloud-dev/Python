import json
from typing import Any
from botocore.exceptions import ClientError
from src.utils.error_utils import except_function
from src.utils.models import Finding, Severity
import logging

logger = logging.getLogger(__name__)


def bucket_policy(client: Any, name: str) -> Finding:
    rule_id = "bucket.policy"
    logger.info(f"Проверка Policy для бакета: {name}")
    try:
        response = client.get_bucket_policy(Bucket=name)
        jsons = json.loads(response["Policy"])
        state = jsons.get("Statement", [])

        public = []

        for i in state:
            effect = i.get("Effect", "")
            pris = i.get("Principal", "")

            if effect == "Allow" and (pris == "*" or pris == {"AWS": "*"}):
                public.append(i)
        if public:
            logger.warning(f"Бакет: {name}: Policy - DANGER")
            return Finding(rule_id, Severity.HIGH, name, "Политика бакета разрешает доступ Principal \"*\"",
                           {"statements": public})
        logger.info(f"Бакет: {name}: Policy - SAFE")
        return Finding(rule_id, Severity.INFO, name, "Политика бакета не открывает публичный доступ")
    except ClientError as e:
        return except_function(e, name, rule_id, ["NoSuchBucketPolicy"], Severity.INFO, "Политика бакета не задана")


def bucket_versioning(client: Any, name: str) -> Finding:
    rule_id = "bucket.versioning"
    logger.info(f"Проверка versioning для бакета: {name}")
    try:
        response = client.get_bucket_versioning(Bucket=name)
        status = response.get("Status", "Suspended")
        logger.info(f"Бакет: {name}: Versioning - status: {status}")
        if status == "Enabled":
            return Finding(rule_id, Severity.INFO, name, "Версионирование включено", {"Status": status})
        return Finding(rule_id, Severity.MEDIUM, name, "Версионирование выключено", {"Status": status})
    except ClientError as e:
        return except_function(e, name, rule_id, [])


def bucket_encrriptyon(client: Any, name: str) -> Finding:
    rule_id = "bucket.encryption"
    logger.info(f"Проверка encriptyon для бакета: {name}")
    try:
        response = client.get_bucket_encryption(Bucket=name)
        rules = response.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        return Finding(rule_id, Severity.INFO, name, "Шифрование по умолчанию включено", {"rules": rules})
    except ClientError as e:
        return except_function(e, name, rule_id, ["ServerSideEncryptionConfigurationNotFoundError"],
                               missing_message="Шифрование по умолчанию не настроено")


def bucket_cors(client: Any, name: str) -> Finding:
    rule_id = "bucket.cors"
    logger.info(f"Проверка cors для бакета: {name}")
    try:
        response = client.get_bucket_cors(Bucket=name)
        rule = response.get("CORSRules", [])

        wildcard = [i for i in rule if "*" in i.get("AllowedOrigins", [])]

        if wildcard:
            logger.warning(f"Бакет: {name}: Cors - DANGER")
            return Finding(rule_id, Severity.HIGH, name, "CORS разрешает любой Origin \"*\"", {"rules": wildcard})
        logger.info(f"Бакет: {name}: Cors - SAFE")
        return Finding(rule_id, Severity.INFO, name, "CORS не разрешает любой Origin")
    except ClientError as e:
        return except_function(e, name, rule_id, ["NoSuchCORSConfiguration"], Severity.INFO, "CORS не задан")


def bucket_lifecycle(client: Any, name: str) -> Finding:
    rule_id = "bucket.lifecycle"
    logger.info(f"Проверка lifecycle для бакета: {name}")
    try:
        response = client.get_bucket_lifecycle_configuration(Bucket=name)
        logger.info(f"Бакет: {name}: lifecycle configuration received")
        rules = response.get("Rules", [])
        return Finding(rule_id, Severity.INFO, name, "Lifecycle-правила настроены", {"rules": rules})
    except ClientError as e:
        return except_function(e, name, rule_id, ["NoSuchLifecycleConfiguration"],
                               missing_message="Lifecycle-правила не настроены")


def bucket_acl(client: Any, name: str) -> Finding:
    rule_id = "bucket.acl"
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
            return Finding(rule_id, Severity.HIGH, name, "ACL выдаёт доступ AllUsers/AuthenticatedUsers",
                           {"grants": reports})
        logger.info(f"Бакет: {name}: Acl - SAFE")
        return Finding(rule_id, Severity.INFO, name, "ACL не выдаёт публичный доступ")
    except ClientError as e:
        return except_function(e, name, rule_id, ["NoSuchBucketAcl"], Severity.INFO, "ACL не задан")


def bucket_mfa(client: Any, name: str) -> Finding:
    rule_id = "bucket.mfa_delete"
    logger.info(f"Проверка mfa для бакета: {name}")
    try:
        response = client.get_bucket_versioning(Bucket=name)
        mfa = response.get("MFADelete", "")

        if not mfa:
            return Finding(rule_id, Severity.LOW, name, "MFA Delete не настроен")
        if mfa == "Disabled":
            logger.warning(f"Бакет: {name}: Mfa - DANGER")
            return Finding(rule_id, Severity.HIGH, name, "MFA Delete выключен", {"MFADelete": mfa})
        logger.info(f"Бакет: {name}: Mfa - SAFE")
        return Finding(rule_id, Severity.INFO, name, "MFA Delete включён", {"MFADelete": mfa})
    except ClientError as e:
        return except_function(e, name, rule_id, [])


def bucket_object(client: Any, name: str) -> Finding:
    rule_id = "bucket.object_lock"
    logger.info(f"Проверка object для бакета: {name}")
    try:
        response = client.get_object_lock_configuration(Bucket=name)
        objects = response.get("ObjectLockConfiguration", {}).get("Rule", {}).get("DefaultRetention", {})

        mode = objects.get("Mode", "")
        days = objects.get("Days", "")
        info = {"Mode": mode, "Days": days}

        if mode == "GOVERNANCE":
            logger.warning(f"Бакет: {name}: Object - DANGER")
            return Finding(rule_id, Severity.HIGH, name, "Object Lock в режиме GOVERNANCE можно обойти", info)
        logger.info(f"Бакет: {name}: Object - SAFE")
        return Finding(rule_id, Severity.INFO, name, "Object Lock настроен", info)
    except ClientError as e:
        return except_function(e, name, rule_id, ["ObjectLockConfigurationNotFoundError"],
                               missing_message="Object Lock не настроен")


def bucket_logging(client: Any, name: str) -> Finding:
    rule_id = "bucket.logging"
    logger.info(f"Проверка logging для бакета: {name}")
    try:
        response = client.get_bucket_logging(Bucket=name)
        log = response.get("LoggingEnabled", {})

        if not log:
            logger.warning(f"Бакет: {name}: Logging - NO_CONFIGURATION")
            return Finding(rule_id, Severity.LOW, name, "Логирование доступа не настроено")
        logger.info(f"Бакет: {name}: Logging - SAFE")
        return Finding(rule_id, Severity.INFO, name, "Логирование доступа включено", {"LoggingEnabled": log})
    except ClientError as e:
        return except_function(e, name, rule_id, [])


def bucket_replication(clients: Any, name: str) -> Finding:
    rule_id = "bucket.replication"
    logger.info(f"Проверка replication для бакета: {name}")
    try:
        response = clients.get_bucket_replication(Bucket=name)
        replication = response.get("ReplicationConfiguration", {}).get("Rules", [])

        if not replication:
            logger.warning(f"Бакет: {name}: Replication - NO_CONFIGURATION")
            return Finding(rule_id, Severity.LOW, name, "Репликация не настроена")

        report = []

        for i in replication:
            statis = i.get("Status", "")
            ids = i.get("ID", "")

            if statis == "Disabled":
                report.append({"Status": statis, "Id": ids})
        if report:
            logger.warning(f"Бакет: {name}: Replication - DANGER")
            return Finding(rule_id, Severity.HIGH, name, "Есть выключенные правила репликации", {"rules": report})
        logger.info(f"Бакет: {name}: Replication - SAFE")
        return Finding(rule_id, Severity.INFO, name, "Репликация включена")
    except ClientError as e:
        return except_function(e, name, rule_id, ["ReplicationConfigurationNotFoundError"],
                               missing_message="Репликация не настроена")
