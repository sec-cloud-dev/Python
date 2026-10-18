import logging
from datetime import datetime, timezone
from src.config import DANGEROUS_ROLES, SAFE_ROLES
from src.inventory import BINDING_SOURCES, CloudInventory
from src.utils.extract_utils import _extract_sa_roles_for_bucket
from src.utils.models import FOLDER_SCOPE, Finding
from src.utils.risk_utils import IAM_SCOPE_EVIDENCE, finding_from_risk, overall_risk

logger = logging.getLogger(__name__)


def check_all_sa_bucket(inventory: CloudInventory) -> Finding:
    """SA roles on Object Storage. Bindings are folder/cloud/organization level, so this is a folder finding."""
    rule_id = "iam.sa_roles"
    logger.info("Проверка SA с доступом к Object Storage")

    missing = inventory.missing(*BINDING_SOURCES)
    results = []
    all_roles = [
        *(inventory.folder_bindings or []),
        *(inventory.cloud_bindings or []),
        *(inventory.organization_bindings or []),
    ]
    all_sa_roles, _ = _extract_sa_roles_for_bucket(all_roles)

    for sa_id, roles in all_sa_roles.items():
        if roles & DANGEROUS_ROLES:
            logger.warning(f"SA: {sa_id} имеет опасные роли на все бакеты папки: {sorted(roles)}")
            risk = "DANGER"
        elif roles & SAFE_ROLES:
            logger.info(f"SA: {sa_id} Имеет безопасные роли: {sorted(roles)}")
            risk = "SAFE"
        else:
            logger.warning(f"SA: {sa_id} Имеет не определенные роли: {sorted(roles)}")
            risk = "WARNING"

        sa = {"sa_id": sa_id, "role": sorted(roles), "risk": risk}

        results.append(sa)

    status_sa = overall_risk(results, risk="risk")
    dangerous = sum(1 for sa in results if sa["risk"] == "DANGER")
    if not results:
        message = "SA с ролями не найдены"
    elif dangerous:
        message = f"SA с опасными ролями на все бакеты папки: {dangerous} из {len(results)}"
    else:
        message = f"SA с ролями: {len(results)}, опасных ролей нет"

    return finding_from_risk(rule_id, FOLDER_SCOPE, status_sa, message, {**IAM_SCOPE_EVIDENCE, "sa_list": results},
                             missing)


def checks_sa_stat_key(inventory: CloudInventory) -> Finding:
    rule_id = "iam.static_keys"
    missing = inventory.missing("service_accounts", "access_keys")
    sa_list = inventory.service_accounts or []
    access_keys = inventory.access_keys or {}
    report = []

    if not sa_list:
        logger.info("Не найдено SA в папке")

    for sa in sa_list:
        name = sa.get("name", "")
        sa_id = sa.get("id", "")
        access_key = access_keys.get(sa_id, [])

        if not access_key:
            logger.info(f"Для SA: {name} Нету статического ключа")
            continue

        for key in access_key:
            key_id = key.get("keyId", "")
            created_at = key.get("createdAt", "")
            last_used = key.get("lastUsedAt", "")

            risk_key_sa = "SAFE"

            if not last_used:
                logger.warning(f"Созданный статический ключ для SA: {name} Не использовался вообще")
                risk_key_sa = "WARNING"

                reports = {
                    "sa_name": name,
                    "key_id": key_id,
                    "created_at": created_at,
                    "last_used": "never",
                    "risk": risk_key_sa,
                }
                report.append(reports)
                continue

            last_usedet = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            days_ago = (now - last_usedet).days

            created = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            days = (now - created).days

            if days_ago >= 90:
                logger.warning(
                    f"Ключ не использовался 90 дней или больше. Забытый/потанциально утекший ключ sa: {name}"
                )
                risk_key_sa = "WARNING"

            if days >= 90:
                logger.warning(
                    f"Ключ у sa: {name} Был создан более чем 90 дней назад риск утечки требуется ротация ключа: {key_id} По 152-фз"
                )
                risk_key_sa = "DANGER"

            reports = {
                "sa_name": name,
                "key_id": key_id,
                "created_at": created_at,
                "last_used": last_used,
                "risk": risk_key_sa,
            }

            report.append(reports)

    over = overall_risk(report, risk="risk")
    if not report:
        message = "Статических ключей у SA нет"
    else:
        stale = sum(1 for r in report if r["risk"] != "SAFE")
        message = f"Статических ключей S3: {len(report)}, требуют внимания: {stale}"

    return finding_from_risk(rule_id, FOLDER_SCOPE, over, message, {"scope": "folder", "keys": report}, missing)
