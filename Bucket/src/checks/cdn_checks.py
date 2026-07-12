import logging
from typing import Any
from src.clients.yandex_client import cdn_originGroup_get, cdn_resources_get
from src.utils.risk_utils import overall_risk

logger = logging.getLogger(__name__)


def bucket_cdn_checkout(folder_id: str, name: str) -> dict[str, Any]:
    logger.info("Проверям связь bukcet - cdn (Не явный публичный доступ к ресурсам)")
    report = []

    group = cdn_originGroup_get(folder_id)
    resources = cdn_resources_get(folder_id)

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

    return {"risk": overall, "report": report}
