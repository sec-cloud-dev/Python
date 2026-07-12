import sys
import os
import json
from unittest.mock import MagicMock
import botocore.exceptions

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.checks.bucket_checks import bucket_policy


def test_bucket_policy_danger():
    mock_s3_client = MagicMock()
    danger_policy = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}

    mock_s3_client.get_bucket_policy.return_value = {"Policy": json.dumps(danger_policy)}

    res = bucket_policy(mock_s3_client, "my-bucket")
    assert res == "DANGER"


def test_bucket_policy_no_policy_exception():
    mock_s3_client = MagicMock()
    error_response = {"Error": {"Code": "NoSuchBucketPolicy", "Message": "The bucket policy does not exist"}}
    mock_s3_client.get_bucket_policy.side_effect = botocore.exceptions.ClientError(error_response, "GetBucketPolicy")

    res = bucket_policy(mock_s3_client, "empty-policy-bucket")
    assert res in ["SAFE", "NO_CONFIGURATION"]
