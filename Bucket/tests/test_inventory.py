from unittest.mock import MagicMock, patch

from src.clients.yandex_client import YandexAPIError
from src.inventory import load_inventory
from src.scanner import live_scan, scan
from src.utils.models import Severity

YC = "src.clients.yandex_client"


def _patch_api(**overrides):
    api = {
        "folder_access_bindings_get": [],
        "cloud_bindings_get": [],
        "organization_id_get": None,
        "organization_bindings_get": [],
        "vm_get": [],
        "sa_get": [{"id": "sa-1", "name": "app"}],
        "access_key_sa": [],
        "triggers_get": [],
        "cdn_originGroup_get": [],
        "cdn_resources_get": [],
        "bucket_get": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
    }
    api.update(overrides)
    patches = {}
    for name, value in api.items():
        mock = MagicMock(side_effect=value) if isinstance(value, Exception) else MagicMock(return_value=value)
        patches[name] = mock
    return patches


def test_failed_source_is_recorded_and_check_is_unknown():
    mocks = _patch_api(folder_access_bindings_get=YandexAPIError("url", 403))
    with patch.multiple(YC, **mocks):
        inventory = load_inventory("folder", "cloud")

    assert inventory.folder_bindings is None
    assert "folder_bindings" in inventory.errors

    result = scan(MagicMock(), inventory, [])
    sa_roles = next(f for f in result.folder_findings if f.rule_id == "iam.sa_roles")
    assert sa_roles.severity is Severity.UNKNOWN


def test_folder_inventory_is_loaded_once_not_per_bucket():
    mocks = _patch_api()
    with patch.multiple(YC, **mocks), patch("src.clients.boto3_client.boto3_logging", return_value=MagicMock()):
        result = live_scan("folder", "cloud")

    assert list(result.buckets) == ["a", "b", "c"]
    for name in ("vm_get", "sa_get", "folder_access_bindings_get", "cloud_bindings_get", "triggers_get"):
        assert mocks[name].call_count == 1, name
    assert mocks["access_key_sa"].call_count == 1  # once per SA, not per bucket
    assert len(result.folder_findings) == 3
