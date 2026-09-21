import io

import boto3

from app.core.config import settings


class S3Storage:
    def __init__(self, client=None):
        if not settings.S3_ENABLED:
            raise RuntimeError("S3 storage is not enabled")
        self.client = client or boto3.client(
            "s3",
            endpoint_url=settings.S3_ENDPOINT or None,
            region_name=settings.S3_REGION,
            aws_access_key_id=settings.S3_ACCESS_KEY.get_secret_value() or None,
            aws_secret_access_key=settings.S3_SECRET_KEY.get_secret_value() or None,
            verify=settings.S3_SECURE,
        )
        self.bucket = settings.S3_BUCKET

    def put_ciphertext(self, object_key: str, content: bytes, content_hash: str) -> dict:
        result = self.client.put_object(
            Bucket=self.bucket,
            Key=object_key,
            Body=io.BytesIO(content),
            ContentLength=len(content),
            ContentType="application/octet-stream",
            Metadata={"ciphertext-sha256": content_hash},
        )
        return {"etag": result.get("ETag", "").strip('"'), "version_id": result.get("VersionId")}

    def get_ciphertext(self, object_key: str) -> bytes:
        return self.client.get_object(Bucket=self.bucket, Key=object_key)["Body"].read()

    def get_ciphertext_metadata(self, object_key: str) -> dict:
        result = self.client.head_object(Bucket=self.bucket, Key=object_key)
        metadata = result.get("Metadata") or {}
        return {
            "size": result.get("ContentLength"),
            "hash": metadata.get("ciphertext-sha256"),
        }

    def delete(self, object_key: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=object_key)
