from unittest.mock import MagicMock, patch

import pytest

from src.clients import yandex_client
from src.clients.yandex_client import YandexAPIError


def _response(status: int, payload: dict) -> MagicMock:
    response = MagicMock(status_code=status)
    response.json.return_value = payload
    return response


@patch("src.clients.yandex_client.requests.get")
def test_http_error_raises_instead_of_empty_result(mock_get):
    mock_get.return_value = _response(403, {})

    with pytest.raises(YandexAPIError):
        yandex_client.folder_access_bindings_get("folder")


@patch("src.clients.yandex_client.requests.get")
def test_list_access_bindings_is_paginated(mock_get):
    mock_get.side_effect = [
        _response(200, {"accessBindings": [{"roleId": "viewer"}], "nextPageToken": "page-2"}),
        _response(200, {"accessBindings": [{"roleId": "storage.admin"}]}),
    ]

    bindings = yandex_client.folder_access_bindings_get("folder")

    assert [b["roleId"] for b in bindings] == ["viewer", "storage.admin"]
    assert "resource-manager.api.cloud.yandex.net" in mock_get.call_args_list[0].args[0]
    assert mock_get.call_args_list[1].kwargs["params"]["pageToken"] == "page-2"


@patch("src.clients.yandex_client.requests.get")
def test_access_keys_use_aws_compatibility_api(mock_get):
    mock_get.return_value = _response(200, {"accessKeys": [{"keyId": "k1"}]})

    assert yandex_client.access_key_sa("sa-1") == [{"keyId": "k1"}]
    assert mock_get.call_args.args[0].endswith("/iam/aws-compatibility/v1/accessKeys")
    assert mock_get.call_args.kwargs["params"] == {"serviceAccountId": "sa-1"}


@patch("src.clients.yandex_client.requests.get")
def test_repeated_page_token_is_an_error(mock_get):
    mock_get.return_value = _response(200, {"accessBindings": [], "nextPageToken": "same"})

    with pytest.raises(YandexAPIError):
        yandex_client.cloud_bindings_get("cloud")
