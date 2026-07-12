import boto3
from src.config import key, secret_key, config


def boto3_logging():
    client = boto3.client(
        "s3",
        endpoint_url="https://storage.yandexcloud.net",
        aws_access_key_id=key,
        aws_secret_access_key=secret_key,
        region_name="ru-central1",
        config=config,
    )
    return client
