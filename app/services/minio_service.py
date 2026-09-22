import io
import json
import logging
import os
import hashlib
from pathlib import Path

from minio import Minio
from minio.error import S3Error

from app.core.config import settings

logger = logging.getLogger(__name__)


class MinioStorage:
    def __init__(self, client=None):
        self.bucket = settings.MINIO_BUCKET
        self.endpoint = settings.MINIO_ENDPOINT
        self.base_dir = Path("storage/minio_data") / self.bucket
        self.client = client
        self._is_local_fallback = False

        if self.client is None:
            try:
                self.client = Minio(
                    settings.MINIO_ENDPOINT,
                    access_key=settings.MINIO_ACCESS_KEY,
                    secret_key=settings.MINIO_SECRET_KEY.get_secret_value(),
                    secure=settings.MINIO_SECURE,
                )
            except Exception as e:
                logger.warning("Error inicializando cliente MinIO: %s. Usando almacenamiento local en disco.", e)
                self._is_local_fallback = True

    def _get_local_path(self, object_key: str) -> Path:
        clean_key = object_key.replace("/", os.sep)
        path = self.base_dir / clean_key
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def _get_local_meta_path(self, object_key: str) -> Path:
        clean_key = object_key.replace("/", os.sep)
        path = self.base_dir / f"{clean_key}.meta.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def ensure_bucket(self) -> None:
        if self._is_local_fallback:
            self.base_dir.mkdir(parents=True, exist_ok=True)
            return

        try:
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
        except Exception as e:
            logger.warning(
                "MinIO no responde en %s (%s). Activando almacenamiento local seguro en disco: %s",
                self.endpoint,
                e,
                self.base_dir,
            )
            self._is_local_fallback = True
            self.base_dir.mkdir(parents=True, exist_ok=True)

    def put_ciphertext(self, object_key: str, content: bytes, content_hash: str) -> dict:
        self.ensure_bucket()
        if self._is_local_fallback:
            path = self._get_local_path(object_key)
            meta_path = self._get_local_meta_path(object_key)
            with open(path, "wb") as f:
                f.write(content)
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump({"hash": content_hash, "size": len(content)}, f)
            return {"etag": hashlib.md5(content).hexdigest()}

        try:
            result = self.client.put_object(
                self.bucket,
                object_key,
                io.BytesIO(content),
                length=len(content),
                content_type="application/octet-stream",
                metadata={"x-amz-meta-ciphertext-sha256": content_hash},
            )
            return {"etag": result.etag}
        except Exception as e:
            logger.warning("Fallo al escribir en MinIO (%s), almacenando localmente en disco.", e)
            self._is_local_fallback = True
            return self.put_ciphertext(object_key, content, content_hash)

    def delete(self, object_key: str) -> None:
        if self._is_local_fallback:
            path = self._get_local_path(object_key)
            meta_path = self._get_local_meta_path(object_key)
            try:
                if path.exists():
                    path.unlink()
                if meta_path.exists():
                    meta_path.unlink()
            except OSError:
                pass
            return

        try:
            self.client.remove_object(self.bucket, object_key)
        except (S3Error, Exception):
            pass

    def get_ciphertext(self, object_key: str) -> bytes:
        if self._is_local_fallback:
            path = self._get_local_path(object_key)
            if not path.exists():
                raise KeyError(f"Objeto no encontrado en almacenamiento local: {object_key}")
            with open(path, "rb") as f:
                return f.read()

        try:
            response = self.client.get_object(self.bucket, object_key)
            try:
                return response.read()
            finally:
                response.close()
                response.release_conn()
        except Exception as e:
            path = self._get_local_path(object_key)
            if path.exists():
                with open(path, "rb") as f:
                    return f.read()
            raise e

    def get_ciphertext_metadata(self, object_key: str) -> dict:
        if self._is_local_fallback:
            path = self._get_local_path(object_key)
            meta_path = self._get_local_meta_path(object_key)
            if not path.exists():
                raise KeyError(f"Objeto no encontrado: {object_key}")
            content_hash = ""
            if meta_path.exists():
                with open(meta_path, "r", encoding="utf-8") as f:
                    content_hash = json.load(f).get("hash", "")
            return {
                "size": path.stat().st_size,
                "hash": content_hash,
            }

        try:
            stat = self.client.stat_object(self.bucket, object_key)
            return {
                "size": stat.size,
                "hash": (stat.metadata or {}).get("X-Amz-Meta-Ciphertext-Sha256")
                or (stat.metadata or {}).get("x-amz-meta-ciphertext-sha256"),
            }
        except Exception as e:
            path = self._get_local_path(object_key)
            if path.exists():
                meta_path = self._get_local_meta_path(object_key)
                content_hash = ""
                if meta_path.exists():
                    with open(meta_path, "r", encoding="utf-8") as f:
                        content_hash = json.load(f).get("hash", "")
                return {"size": path.stat().st_size, "hash": content_hash}
            raise e
