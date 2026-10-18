import logging
from dataclasses import dataclass, field
from typing import Any, Callable, TypeVar

from requests.exceptions import RequestException

from src.clients import yandex_client
from src.clients.yandex_client import YandexAPIError

logger = logging.getLogger(__name__)

T = TypeVar("T")

BINDING_SOURCES = ("folder_bindings", "cloud_bindings", "organization_bindings")


@dataclass
class CloudInventory:
    """Folder-wide data loaded once per scan and shared by every bucket.

    A source is None when it could not be fetched; checks must report UNKNOWN for it, never SAFE.
    """

    folder_id: str
    cloud_id: str
    folder_bindings: list[dict[str, Any]] | None = None
    cloud_bindings: list[dict[str, Any]] | None = None
    organization_bindings: list[dict[str, Any]] | None = None
    vms: list[dict[str, Any]] | None = None
    service_accounts: list[dict[str, Any]] | None = None
    access_keys: dict[str, list[dict[str, Any]]] | None = None
    triggers: list[dict[str, Any]] | None = None
    cdn_origin_groups: list[dict[str, Any]] | None = None
    cdn_resources: list[dict[str, Any]] | None = None
    errors: dict[str, str] = field(default_factory=dict)

    def missing(self, *sources: str) -> list[str]:
        return [source for source in sources if getattr(self, source) is None]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "CloudInventory":
        """Build an inventory from an offline fixture. An explicit null simulates a failed API call."""
        iam = data.get("iam", {})
        cdn = data.get("cdn", {})
        return cls(
            folder_id=data.get("folder_id", "fixture-folder"),
            cloud_id=data.get("cloud_id", "fixture-cloud"),
            folder_bindings=iam.get("folder_bindings", []),
            cloud_bindings=iam.get("cloud_bindings", []),
            organization_bindings=iam.get("organization_bindings", []),
            vms=data.get("vms", []),
            service_accounts=data.get("service_accounts", []),
            access_keys=data.get("access_keys", {}),
            triggers=data.get("triggers", []),
            cdn_origin_groups=cdn.get("origin_groups", []),
            cdn_resources=cdn.get("resources", []),
        )


def _organization_bindings() -> list[dict[str, Any]]:
    organization_id = yandex_client.organization_id_get()
    return yandex_client.organization_bindings_get(organization_id) if organization_id else []


def _access_keys(service_accounts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    return {sa["id"]: yandex_client.access_key_sa(sa["id"]) for sa in service_accounts if sa.get("id")}


def load_inventory(folder_id: str, cloud_id: str) -> CloudInventory:
    inventory = CloudInventory(folder_id=folder_id, cloud_id=cloud_id)

    def fetch(source: str, loader: Callable[[], T]) -> T | None:
        try:
            return loader()
        except (YandexAPIError, RequestException) as exc:
            logger.error("Не удалось получить %s: %s", source, exc)
            inventory.errors[source] = str(exc)
            return None

    inventory.folder_bindings = fetch("folder_bindings", lambda: yandex_client.folder_access_bindings_get(folder_id))
    inventory.cloud_bindings = fetch("cloud_bindings", lambda: yandex_client.cloud_bindings_get(cloud_id))
    inventory.organization_bindings = fetch("organization_bindings", _organization_bindings)
    inventory.vms = fetch("vms", lambda: yandex_client.vm_get(folder_id))
    inventory.service_accounts = fetch("service_accounts", lambda: yandex_client.sa_get(folder_id))
    service_accounts = inventory.service_accounts
    if service_accounts is not None:
        inventory.access_keys = fetch("access_keys", lambda: _access_keys(service_accounts))
    inventory.triggers = fetch("triggers", lambda: yandex_client.triggers_get(folder_id))
    inventory.cdn_origin_groups = fetch("cdn_origin_groups", lambda: yandex_client.cdn_originGroup_get(folder_id))
    inventory.cdn_resources = fetch("cdn_resources", lambda: yandex_client.cdn_resources_get(folder_id))
    return inventory
