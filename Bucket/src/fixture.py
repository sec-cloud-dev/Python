"""Offline fixture: fake S3 responses and folder inventory, so scans run without Yandex credentials."""
import json
from pathlib import Path
from typing import Any, Callable

from botocore.exceptions import ClientError

from src.inventory import CloudInventory

# boto3 method -> (fixture key, error code when the key is absent or None, response builder)
_S3_METHODS: dict[str, tuple[str, str | None, Callable[[Any], dict[str, Any]]]] = {
    "get_bucket_policy": ("policy", "NoSuchBucketPolicy", lambda v: {"Policy": json.dumps(v)}),
    "get_bucket_versioning": ("versioning", None, dict),
    "get_bucket_encryption": (
        "encryption", "ServerSideEncryptionConfigurationNotFoundError",
        lambda v: {"ServerSideEncryptionConfiguration": v},
    ),
    "get_bucket_cors": ("cors", "NoSuchCORSConfiguration", lambda v: {"CORSRules": v}),
    "get_bucket_lifecycle_configuration": ("lifecycle", "NoSuchLifecycleConfiguration", lambda v: {"Rules": v}),
    "get_bucket_acl": ("acl", None, lambda v: {"Grants": v}),
    "get_object_lock_configuration": (
        "object_lock", "ObjectLockConfigurationNotFoundError", lambda v: {"ObjectLockConfiguration": v},
    ),
    "get_bucket_logging": ("logging", None, lambda v: {"LoggingEnabled": v}),
    "get_bucket_replication": (
        "replication", "ReplicationConfigurationNotFoundError", lambda v: {"ReplicationConfiguration": v},
    ),
}


class FixtureS3Client:
    """Answers the boto3 calls used by bucket checks from a fixture dict."""

    def __init__(self, buckets: dict[str, dict[str, Any]]):
        self._buckets = buckets

    def __getattr__(self, method: str) -> Callable[..., dict[str, Any]]:
        if method not in _S3_METHODS:
            raise AttributeError(method)
        key, missing_code, build = _S3_METHODS[method]

        def call(Bucket: str) -> dict[str, Any]:
            if Bucket not in self._buckets:
                raise ClientError({"Error": {"Code": "NoSuchBucket", "Message": Bucket}}, method)
            value = self._buckets[Bucket].get(key)
            if value is None:
                if missing_code:
                    raise ClientError({"Error": {"Code": missing_code, "Message": key}}, method)
                return {}
            return build(value)

        return call


def load_fixture(path: str | Path) -> tuple[FixtureS3Client, CloudInventory, list[str]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    buckets = data.get("buckets", {})
    return FixtureS3Client(buckets), CloudInventory.from_dict(data), list(buckets)
