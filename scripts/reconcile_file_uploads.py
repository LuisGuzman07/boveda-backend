"""Reconcile expired CU08 uploads and terminal ciphertext objects safely."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.database import SessionLocal
from app.services.file_upload_service import FileUploadService
from app.services.object_storage import MinioObjectStorage, ObjectStorageUnavailable


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconcile expired encrypted file uploads.")
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()
    if args.limit < 1 or args.limit > 1000:
        parser.error("--limit must be between 1 and 1000")

    try:
        storage = MinioObjectStorage()
    except ObjectStorageUnavailable:
        print("Object storage is not configured.", file=sys.stderr)
        return 1

    db = SessionLocal()
    try:
        service = FileUploadService(db, storage)
        expired = service.reconcile_expired_uploads(args.limit)
        terminal = service.reconcile_terminal_objects(args.limit)
    finally:
        db.close()
    print(f"Reconciled {expired} expired uploads and {terminal} terminal objects.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
