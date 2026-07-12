import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.checks.vm_checks import checks_vm_sa_bucket_access


@patch("src.checks.vm_checks.vm_get")
@patch("src.checks.vm_checks.folder_access_bindings_get")
@patch("src.checks.vm_checks.cloud_bindings_get")
@patch("src.checks.vm_checks.organization_bindings_get")
@patch("src.checks.vm_checks.organization_id_get")
def test_vm_public_ip_with_dangerous_role(
    mock_org_id, mock_org_bindings, mock_cloud_bindings, mock_folder_bindings, mock_vm_get
):

    mock_org_id.return_value = "fake-org-id"

    mock_vm_get.return_value = [
        {
            "id": "vm-123",
            "name": "hacked-vm",
            "serviceAccountId": "sa-admin-id",
            "networkInterfaces": [{"primaryV4Address": {"oneToOneNat": {"address": "8.8.8.8"}}}],
        }
    ]

    mock_folder_bindings.return_value = [
        {"roleId": "admin", "subject": {"id": "sa-admin-id", "type": "serviceAccount"}}
    ]

    mock_cloud_bindings.return_value = []
    mock_org_bindings.return_value = []

    result = checks_vm_sa_bucket_access(folder_id="fake-folder", cloud_id="fake-cloud", bucket_name="my-secret-bucket")

    assert result["status"] == "DANGER"
    assert len(result["chains"]) == 1

    chain = result["chains"][0]
    assert chain["vm_name"] == "hacked-vm"
    assert chain["public_ip"] is True
    assert chain["risk"] == "DANGER"
    assert "admin" in chain["roles"]