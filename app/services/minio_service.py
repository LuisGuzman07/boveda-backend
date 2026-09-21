import io

from minio import Minio
from minio.error import S3Error

from app.core.config import settings


class MinioStorage:
    def __init__(self, client=None):
        self.client = client or Minio(
            settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY.get_secret_value(),
            secure=settings.MINIO_SECURE,
        )
        self.bucket = settings.MINIO_BUCKET

    def ensure_bucket(self) -> None:
        if not self.client.bucket_exists(self.bucket):
            self.client.make_bucket(self.bucket)

    def put_ciphertext(self, object_key: str, content: bytes, content_hash: str) -> dict:
        self.ensure_bucket()
        result = self.client.put_object(
            self.bucket,
            object_key,
            io.BytesIO(content),
            length=len(content),
            content_type="application/octet-stream",
            metadata={"x-amz-meta-ciphertext-sha256": content_hash},
        )
        return {"etag": result.etag}

    def delete(self, object_key: str) -> None:
        try:
            self.client.remove_object(self.bucket, object_key)
        except S3Error:
            pass

    def get_ciphertext(self, object_key: str) -> bytes:
        response = self.client.get_object(self.bucket, object_key)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def get_ciphertext_metadata(self, object_key: str) -> dict:
        stat = self.client.stat_object(self.bucket, object_key)
        return {
            "size": stat.size,
            "hash": (stat.metadata or {}).get("X-Amz-Meta-Ciphertext-Sha256")
            or (stat.metadata or {}).get("x-amz-meta-ciphertext-sha256"),
        }
