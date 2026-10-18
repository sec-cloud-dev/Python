import logging
from src.inventory import CloudInventory
from src.utils.models import Finding
from src.utils.risk_utils import finding_from_risk, overall_risk

logger = logging.getLogger(__name__)


def bucket_cdn_checkout(inventory: CloudInventory, name: str) -> Finding:
    rule_id = "cdn.origin"
    logger.info("Проверям связь bukcet - cdn (Не явный публичный доступ к ресурсам)")
    missing = inventory.missing("cdn_origin_groups", "cdn_resources")
    report = []

    group = inventory.cdn_origin_groups or []
    resources = inventory.cdn_resources or []

    for i in group:
        ids = i.get("id", "")

        if not ids:
            continue

        bucket_found = False
        for origin in i.get("origins", []):
            names = origin.get("meta", {}).get("bucket", {}).get("name", "")
            if names == name:
                bucket_found = True
                break

        if not bucket_found:
            continue

        for res in resources:
            active = res.get("active", False)
            origin_id = res.get("originGroupId", "")
            protocol = res.get("originProtocol", "")

            if ids == origin_id:
                if active:
                    risk = "DANGER"
                else:
                    risk = "SAFE"

                chains = {
                    "Bucket_name": name,
                    "Risk": risk,
                    "Protocol": protocol,
                    "Origin_id": origin_id,
                    "Group_id": ids,
                    "Status": active,
                }

                report.append(chains)
    overall = overall_risk(report, risk="Risk")
    active_count = sum(1 for c in report if c["Status"])
    if active_count:
        message = f"Бакет раздаётся через активный CDN-ресурс: {active_count}"
    else:
        message = "Активных CDN-ресурсов с этим бакетом нет"

    return finding_from_risk(rule_id, name, overall, message, {"resources": report}, missing)
