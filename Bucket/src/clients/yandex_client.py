import logging
from typing import Any

import requests
from requests.exceptions import ConnectionError, Timeout
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from src.config import token

logger = logging.getLogger(__name__)


class YandexAPIError(RuntimeError):
    """An API request failed and the result must not be treated as empty."""

    def __init__(self, url: str, status_code: int | None = None):
        self.url = url
        self.status_code = status_code
        suffix = f" (HTTP {status_code})" if status_code is not None else ""
        super().__init__(f"Yandex Cloud API request failed{suffix}: {url}")


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, (ConnectionError, Timeout)):
        return True
    if not isinstance(exc, YandexAPIError):
        return False
    return exc.status_code is None or exc.status_code == 429 or exc.status_code >= 500


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=1, max=10),
    retry=retry_if_exception(_is_retryable),
    reraise=True,
)
def yc_get(url: str, params: dict[str, str] | None = None) -> dict[str, Any]:
    """Perform an authenticated API request without hiding failures."""
    logger.info("Запрос к api: %s", url)
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)
    except (ConnectionError, Timeout):
        logger.exception("Ошибка соединения с API: %s", url)
        raise

    if not 200 <= response.status_code < 300:
        logger.error("API error: %s - HTTP %s", url, response.status_code)
        raise YandexAPIError(url, response.status_code)

    try:
        data = response.json()
    except ValueError as exc:
        logger.error("API returned invalid JSON: %s", url)
        raise YandexAPIError(url, response.status_code) from exc

    if not isinstance(data, dict):
        logger.error("API returned an unexpected response shape: %s", url)
        raise YandexAPIError(url, response.status_code)
    return data


def get_all_pages(url: str, params: dict[str, str], key: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    request_params = dict(params)
    seen_tokens: set[str] = set()

    while True:
        data = yc_get(url, request_params)
        page_items = data.get(key, [])
        if not isinstance(page_items, list):
            raise YandexAPIError(url)
        items.extend(item for item in page_items if isinstance(item, dict))

        next_token = data.get("nextPageToken")
        if not next_token:
            return items
        if not isinstance(next_token, str) or next_token in seen_tokens:
            raise YandexAPIError(url)
        seen_tokens.add(next_token)
        request_params["pageToken"] = next_token


def bucket_get(folder_id: str) -> list[dict[str, Any]]:
    return get_all_pages("https://storage.api.cloud.yandex.net/storage/v1/buckets", {"folderId": folder_id}, "buckets")


def vm_get(folder_id: str) -> list[dict[str, Any]]:
    return get_all_pages("https://compute.api.cloud.yandex.net/compute/v1/instances", {"folderId": folder_id}, "instances")


def folder_access_bindings_get(folder_id: str) -> list[dict[str, Any]]:
    """Folder bindings come from Resource Manager, paginated."""
    url = f"https://resource-manager.api.cloud.yandex.net/resource-manager/v1/folders/{folder_id}:listAccessBindings"
    return get_all_pages(url, {}, "accessBindings")


def organization_id_get() -> str | None:
    data = yc_get("https://organization-manager.api.cloud.yandex.net/organization-manager/v1/organizations")
    organizations = data.get("organizations", [])
    if organizations and isinstance(organizations[0], dict):
        return organizations[0].get("id")
    return None


def organization_bindings_get(organization_id: str) -> list[dict[str, Any]]:
    url = f"https://organization-manager.api.cloud.yandex.net/organization-manager/v1/organizations/{organization_id}:listAccessBindings"
    return get_all_pages(url, {}, "accessBindings")


def cloud_bindings_get(cloud_id: str) -> list[dict[str, Any]]:
    url = f"https://resource-manager.api.cloud.yandex.net/resource-manager/v1/clouds/{cloud_id}:listAccessBindings"
    return get_all_pages(url, {}, "accessBindings")


def access_key_sa(sa_id: str) -> list[dict[str, Any]]:
    """S3 static keys of a service account (IAM aws-compatibility API)."""
    return get_all_pages("https://iam.api.cloud.yandex.net/iam/aws-compatibility/v1/accessKeys", {"serviceAccountId": sa_id}, "accessKeys")


def sa_get(folder_id: str) -> list[dict[str, Any]]:
    return get_all_pages("https://iam.api.cloud.yandex.net/iam/v1/serviceAccounts", {"folderId": folder_id}, "serviceAccounts")


def triggers_get(folder_id: str) -> list[dict[str, Any]]:
    return get_all_pages("https://serverless-triggers.api.cloud.yandex.net/triggers/v1/triggers", {"folderId": folder_id}, "triggers")


def cdn_resources_get(folder_id: str) -> list[dict[str, Any]]:
    return get_all_pages("https://cdn.api.cloud.yandex.net/cdn/v1/resources", {"folderId": folder_id}, "resources")


def cdn_originGroup_get(folder_id: str) -> list[dict[str, Any]]:
    return get_all_pages("https://cdn.api.cloud.yandex.net/cdn/v1/originGroups", {"folderId": folder_id}, "originGroups")
