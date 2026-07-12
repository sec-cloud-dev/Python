import requests
import logging
from typing import Any
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from requests.exceptions import ConnectionError, Timeout
from src.config import token

logger = logging.getLogger(__name__)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=10),
    retry=retry_if_exception_type((ConnectionError, Timeout)),
)
def yc_get(url: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    logger.info(f"Запрос к api: {url}")
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, params=params, timeout=30)

    if response.status_code != 200:
        logger.error(f"ERROR: {url} - Code: {response.status_code}")
        return {}
    return response.json()


def get_all_pages(url: str, params: dict[str, str], key: str) -> list[dict[str, Any]]:
    items = []
    tok = None

    while True:
        if tok:
            params["pageToken"] = tok
        data = yc_get(url, params)
        items += data.get(key, [])

        tok = data.get("nextPageToken")
        if not tok:
            break
    return items


def bucket_get(folder_id: str) -> list[dict[str, Any]]:
    url = "https://storage.api.cloud.yandex.net/storage/v1/buckets"
    return get_all_pages(url, {"folderId": folder_id}, "buckets")


def vm_get(folder_id: str) -> list[dict[str, Any]]:
    url = "https://compute.api.cloud.yandex.net/compute/v1/instances"
    return get_all_pages(url, {"folderId": folder_id}, "instances")


def folder_access_bindings_get(folder_id: str) -> list[dict[str, Any]]:
    url = f"https://resource-manager.api.cloud.yandex.net/resource-manager/v1/folders/{folder_id}:listAccessBindings"
    data = yc_get(url)
    return data.get("accessBindings", [])


def organization_id_get() -> str | None:
    url = "https://organization-manager.api.cloud.yandex.net/organization-manager/v1/organizations"
    data = yc_get(url)
    organization = data.get("organizations", [])
    if organization:
        return organization[0]["id"]
    return None


def organization_bindings_get(id: str) -> list[dict[str, Any]]:
    url = f"https://organization-manager.api.cloud.yandex.net/organization-manager/v1/organizations/{id}:listAccessBindings"
    data = yc_get(url)
    return data.get("accessBindings", [])


def cloud_bindings_get(cloud_id: str) -> list[dict[str, Any]]:
    url = f"https://resource-manager.api.cloud.yandex.net/resource-manager/v1/clouds/{cloud_id}:listAccessBindings"
    data = yc_get(url)
    return data.get("accessBindings", [])


def access_key_sa(sa_id: str) -> list[dict[str, Any]]:
    url = "https://iam.api.cloud.yandex.net/iam/aws-compatibility/v1/accessKeys"
    params = {"serviceAccountId": sa_id}
    data = yc_get(url, params)
    return data.get("accessKeys", [])


def sa_get(folder_id: str) -> list[dict[str, Any]]:
    url = "https://iam.api.cloud.yandex.net/iam/v1/serviceAccounts"
    return get_all_pages(url, {"folderId": folder_id}, "serviceAccounts")


def triggers_get(folder_id: str) -> list[dict[str, Any]]:
    url = "https://serverless-triggers.api.cloud.yandex.net/triggers/v1/triggers"
    return get_all_pages(url, {"folderId": folder_id}, "triggers")


def cdn_resources_get(folder_id: str) -> list[dict[str, Any]]:
    url = "https://cdn.api.cloud.yandex.net/cdn/v1/resources"
    return get_all_pages(url, {"folderId": folder_id}, "resources")


def cdn_originGroup_get(folder_id: str) -> list[dict[str, Any]]:
    url = "https://cdn.api.cloud.yandex.net/cdn/v1/originGroups"
    return get_all_pages(url, {"folderId": folder_id}, "originGroups")
