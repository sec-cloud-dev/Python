import json
from unittest.mock import MagicMock

import botocore.exceptions

from src.checks.bucket_checks import bucket_acl, bucket_policy, bucket_versioning
from src.utils.models import Finding, Severity


def _client_error(code: str, operation: str) -> botocore.exceptions.ClientError:
    return botocore.exceptions.ClientError({"Error": {"Code": code, "Message": code}}, operation)


def test_bucket_policy_danger():
    mock_s3_client = MagicMock()
    danger_policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}

    mock_s3_client.get_bucket_policy.return_value = {"Policy": json.dumps(danger_policy)}
    res = bucket_policy(mock_s3_client, "my-bucket")

    assert isinstance(res, Finding)
    assert res.rule_id == "bucket.policy"
    assert res.severity is Severity.HIGH
    assert res.bucket == "my-bucket"
    assert res.evidence["statements"] == danger_policy["Statement"]


def test_bucket_policy_no_policy_exception():
    mock_s3_client = MagicMock()
    mock_s3_client.get_bucket_policy.side_effect = _client_error("NoSuchBucketPolicy", "GetBucketPolicy")

    res = bucket_policy(mock_s3_client, "empty-policy-bucket")
    assert res.severity is Severity.INFO


def test_bucket_policy_access_denied_is_unknown_not_safe():
    mock_s3_client = MagicMock()
    mock_s3_client.get_bucket_policy.side_effect = _client_error("AccessDenied", "GetBucketPolicy")

    res = bucket_policy(mock_s3_client, "locked-bucket")
    assert res.severity is Severity.UNKNOWN
    assert res.evidence["error_code"] == "AccessDenied"


def test_bucket_acl_public_is_high_finding():
    mock_s3_client = MagicMock()
    mock_s3_client.get_bucket_acl.return_value = {
        "Grants": [
            {"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}
        ]
    }

    res = bucket_acl(mock_s3_client, "public")
    assert res.severity is Severity.HIGH
    assert res.evidence["grants"][0]["Permission"] == "READ"


def test_bucket_versioning_suspended_is_medium():
    mock_s3_client = MagicMock()
    mock_s3_client.get_bucket_versioning.return_value = {"Status": "Suspended"}

    assert bucket_versioning(mock_s3_client, "b").severity is Severity.MEDIUM
