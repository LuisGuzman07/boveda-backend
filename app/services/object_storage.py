"""Minimal provider boundary for ciphertext-only object storage."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

from fastapi import HTTPException
from minio import Minio
from minio.commonconfig import CopySource
from minio.error import S3Error

from app.core.config import Settings, settings


class ObjectStorageError(RuntimeError):
    """Base error intentionally kept free of storage endpoint details."""


class ObjectStorageUnavailable(ObjectStorageError):
    pass


class ObjectStorageObjectMissing(ObjectStorageError):
    pass


class ObjectStorageIntegrityError(ObjectStorageError):
    pass


@dataclass(frozen=True)
class StoredCiphertext:
    size: int
    sha256: str
    etag: str | None


class ObjectStorage(Protocol):
    def create_upload_url(
        self,
        staging_object_key: str,
        expected_size: int,
        expires_in: timedelta,
    ) -> str: ...

    def finalize_ciphertext(
        self,
        staging_object_key: str,
        final_object_key: str,
        expected_size: int,
        expected_sha256: str,
    ) -> StoredCiphertext: ...

    def delete_object(self, object_key: str) -> None: ...


class MinioObjectStorage:
    """MinIO adapter that handles only opaque ciphertext object keys."""

    def __init__(self, configured: Settings = settings):
        if not configured.OBJECT_STORAGE_ENABLED:
            raise ObjectStorageUnavailable("Object storage is not configured.")
        access_key = configured.MINIO_ACCESS_KEY
        secret_key = configured.MINIO_SECRET_KEY
        if access_key is None or secret_key is None:
            raise ObjectStorageUnavailable("Object storage is not configured.")
        self._bucket = configured.MINIO_BUCKET
        self._region = configured.MINIO_REGION
        self._access_key = access_key.get_secret_value()
        self._secret_key = secret_key.get_secret_value()
        self._internal = Minio(
            configured.MINIO_INTERNAL_ENDPOINT,
            access_key=self._access_key,
            secret_key=self._secret_key,
            secure=configured.MINIO_SECURE,
            region=self._region,
        )
        public_endpoint = urlsplit(configured.MINIO_PUBLIC_ENDPOINT)
        self._public_scheme = public_endpoint.scheme
        self._public_netloc = public_endpoint.netloc

    @staticmethod
    def _signing_key(secret_key: str, date_stamp: str, region: str) -> bytes:
        date_key = hmac.new(
            f"AWS4{secret_key}".encode("utf-8"), date_stamp.encode("ascii"), hashlib.sha256
        ).digest()
        region_key = hmac.new(date_key, region.encode("utf-8"), hashlib.sha256).digest()
        service_key = hmac.new(region_key, b"s3", hashlib.sha256).digest()
        return hmac.new(service_key, b"aws4_request", hashlib.sha256).digest()

    def create_upload_url(
        self,
        staging_object_key: str,
        expected_size: int,
        expires_in: timedelta,
    ) -> str:
        """Issue a PUT capability bound to one opaque staging key and byte length."""

        if expected_size < 0:
            raise ObjectStorageIntegrityError("Ciphertext size cannot be negative.")
        try:
            expires = int(expires_in.total_seconds())
            if not 1 <= expires <= 604800:
                raise ValueError("Presigned expiry is outside the S3 range.")
            now = datetime.now(timezone.utc)
            date_stamp = now.strftime("%Y%m%d")
            amz_date = now.strftime("%Y%m%dT%H%M%SZ")
            credential = f"{self._access_key}/{date_stamp}/{self._region}/s3/aws4_request"
            query = {
                "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
                "X-Amz-Credential": credential,
                "X-Amz-Date": amz_date,
                "X-Amz-Expires": expires,
                "X-Amz-SignedHeaders": "content-length;host",
            }
            canonical_query = urlencode(
                sorted(query.items()), quote_via=quote, safe="~-._"
            )
            canonical_uri = "/" + quote(
                f"{self._bucket}/{staging_object_key}", safe="/-_.~"
            )
            canonical_headers = f"content-length:{expected_size}\nhost:{self._public_netloc}\n"
            canonical_request = (
                f"PUT\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n"
                "content-length;host\nUNSIGNED-PAYLOAD"
            )
            scope = f"{date_stamp}/{self._region}/s3/aws4_request"
            string_to_sign = (
                "AWS4-HMAC-SHA256\n"
                f"{amz_date}\n{scope}\n{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
            )
            signature = hmac.new(
                self._signing_key(self._secret_key, date_stamp, self._region),
                string_to_sign.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            query["X-Amz-Signature"] = signature
            return urlunsplit(
                (
                    self._public_scheme,
                    self._public_netloc,
                    canonical_uri,
                    urlencode(sorted(query.items()), quote_via=quote, safe="~-._"),
                    "",
                )
            )
        except Exception as error:
            raise ObjectStorageUnavailable("Unable to issue the upload capability.") from error

    def _verify_ciphertext(
        self,
        object_key: str,
        expected_size: int,
        expected_sha256: str,
    ) -> StoredCiphertext:
        try:
            stat = self._internal.stat_object(self._bucket, object_key)
        except S3Error as error:
            if error.code in {"NoSuchKey", "NoSuchObject", "NoSuchBucket"}:
                raise ObjectStorageObjectMissing("Ciphertext object is absent.") from error
            raise ObjectStorageUnavailable("Unable to inspect ciphertext storage.") from error
        except Exception as error:
            raise ObjectStorageUnavailable("Unable to inspect ciphertext storage.") from error

        if stat.size != expected_size:
            raise ObjectStorageIntegrityError("Ciphertext size does not match.")

        digest = hashlib.sha256()
        response = None
        try:
            response = self._internal.get_object(self._bucket, object_key)
            while chunk := response.read(64 * 1024):
                digest.update(chunk)
        except S3Error as error:
            if error.code in {"NoSuchKey", "NoSuchObject", "NoSuchBucket"}:
                raise ObjectStorageObjectMissing("Ciphertext object is absent.") from error
            raise ObjectStorageUnavailable("Unable to read ciphertext storage.") from error
        except Exception as error:
            raise ObjectStorageUnavailable("Unable to read ciphertext storage.") from error
        finally:
            if response is not None:
                response.close()
                response.release_conn()

        actual_sha256 = digest.hexdigest()
        if actual_sha256 != expected_sha256:
            raise ObjectStorageIntegrityError("Ciphertext checksum does not match.")
        return StoredCiphertext(size=stat.size, sha256=actual_sha256, etag=stat.etag)

    def finalize_ciphertext(
        self,
        staging_object_key: str,
        final_object_key: str,
        expected_size: int,
        expected_sha256: str,
    ) -> StoredCiphertext:
        """Copy verified staging ciphertext to a key no presigned URL can mutate."""

        staged = self._verify_ciphertext(
            staging_object_key,
            expected_size,
            expected_sha256,
        )
        if not staged.etag:
            raise ObjectStorageUnavailable("Ciphertext storage did not return an ETag.")
        try:
            self._internal.copy_object(
                self._bucket,
                final_object_key,
                CopySource(
                    self._bucket,
                    staging_object_key,
                    match_etag=staged.etag,
                ),
            )
        except S3Error as error:
            if error.code in {"NoSuchKey", "NoSuchObject", "NoSuchBucket"}:
                raise ObjectStorageObjectMissing("Ciphertext object is absent.") from error
            if error.code in {"PreconditionFailed", "InvalidRequest"}:
                raise ObjectStorageIntegrityError("Ciphertext changed during finalization.") from error
            raise ObjectStorageUnavailable("Unable to finalize ciphertext storage.") from error
        except Exception as error:
            raise ObjectStorageUnavailable("Unable to finalize ciphertext storage.") from error
        return self._verify_ciphertext(final_object_key, expected_size, expected_sha256)

    def delete_object(self, object_key: str) -> None:
        try:
            self._internal.remove_object(self._bucket, object_key)
        except S3Error as error:
            if error.code in {"NoSuchKey", "NoSuchObject", "NoSuchBucket"}:
                return
            raise ObjectStorageUnavailable("Unable to remove ciphertext storage.") from error
        except Exception as error:
            raise ObjectStorageUnavailable("Unable to remove ciphertext storage.") from error


def get_object_storage() -> ObjectStorage:
    """FastAPI dependency; tests replace it with an in-memory ciphertext fake."""

    try:
        return MinioObjectStorage()
    except ObjectStorageUnavailable as error:
        raise HTTPException(503, "El almacenamiento cifrado no está disponible.") from error
