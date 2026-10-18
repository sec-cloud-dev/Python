from datetime import datetime, timedelta, timezone

from src.checks.sa_checks import check_all_sa_bucket, checks_sa_stat_key
from src.inventory import CloudInventory
from src.utils.models import FOLDER_SCOPE, Severity


def _inventory(**sources) -> CloudInventory:
    defaults = dict(
        folder_bindings=[], cloud_bindings=[], organization_bindings=[], vms=[], service_accounts=[],
        access_keys={}, triggers=[], cdn_origin_groups=[], cdn_resources=[],
    )
    defaults.update(sources)
    return CloudInventory(folder_id="f", cloud_id="c", **defaults)


def test_checks_sa_stat_key_danger_and_never_used():
    now = datetime.now(timezone.utc)
    old_date_str = (now - timedelta(days=100)).isoformat().replace("+00:00", "Z")
    new_date_str = now.isoformat().replace("+00:00", "Z")

    inventory = _inventory(
        service_accounts=[{"id": "sa-1", "name": "danger-sa"}, {"id": "sa-2", "name": "warning-sa"}],
        access_keys={
            "sa-1": [{"keyId": "key-old", "createdAt": old_date_str, "lastUsedAt": new_date_str}],
            "sa-2": [{"keyId": "key-never", "createdAt": new_date_str, "lastUsedAt": None}],
        },
    )

    result = checks_sa_stat_key(inventory)

    assert result.rule_id == "iam.static_keys"
    assert result.severity is Severity.HIGH
    keys = result.evidence["keys"]
    assert len(keys) == 2

    assert keys[0]["sa_name"] == "danger-sa"
    assert keys[0]["risk"] == "DANGER"

    assert keys[1]["sa_name"] == "warning-sa"
    assert keys[1]["last_used"] == "never"
    assert keys[1]["risk"] == "WARNING"


def test_static_keys_unavailable_is_unknown():
    inventory = _inventory(service_accounts=[{"id": "sa-1", "name": "app"}], access_keys=None)
    assert checks_sa_stat_key(inventory).severity is Severity.UNKNOWN


def test_sa_roles_are_reported_as_folder_level():
    inventory = _inventory(
        folder_bindings=[{"roleId": "storage.admin", "subject": {"id": "sa-1", "type": "serviceAccount"}}]
    )

    finding = check_all_sa_bucket(inventory)

    assert finding.severity is Severity.HIGH
    assert finding.bucket == FOLDER_SCOPE
    assert finding.evidence["scope"] == "folder"
    assert "bucket-level bindings не запрашивались" in finding.evidence["note"]
