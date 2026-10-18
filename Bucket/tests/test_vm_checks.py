from src.checks.vm_checks import checks_vm_sa_bucket_access
from src.inventory import CloudInventory
from src.utils.models import Severity


def test_vm_public_ip_with_dangerous_role():
    inventory = CloudInventory(
        folder_id="fake-folder",
        cloud_id="fake-cloud",
        vms=[
            {
                "id": "vm-123",
                "name": "hacked-vm",
                "serviceAccountId": "sa-admin-id",
                "networkInterfaces": [{"primaryV4Address": {"oneToOneNat": {"address": "8.8.8.8"}}}],
            }
        ],
        folder_bindings=[{"roleId": "admin", "subject": {"id": "sa-admin-id", "type": "serviceAccount"}}],
        cloud_bindings=[],
        organization_bindings=[],
    )

    result = checks_vm_sa_bucket_access(inventory)

    assert result.severity is Severity.HIGH
    chains = result.evidence["chains"]
    assert len(chains) == 1

    chain = chains[0]
    assert chain["vm_name"] == "hacked-vm"
    assert chain["public_ip"] is True
    assert chain["risk"] == "DANGER"
    assert "admin" in chain["roles"]


def test_vm_check_with_failed_bindings_is_unknown():
    inventory = CloudInventory(
        folder_id="f", cloud_id="c", vms=[], folder_bindings=None, cloud_bindings=[], organization_bindings=[]
    )

    result = checks_vm_sa_bucket_access(inventory)

    assert result.severity is Severity.UNKNOWN
    assert result.evidence["missing_sources"] == ["folder_bindings"]
