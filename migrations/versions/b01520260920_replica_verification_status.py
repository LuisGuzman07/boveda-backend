"""CU-15 replica verification statuses."""

from alembic import op


revision = "b01520260920"
down_revision = "a01320260920"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TABLE replica_almacenamiento DROP CONSTRAINT IF EXISTS ck_replica_estado")
    op.execute("UPDATE replica_almacenamiento SET estado = 'PENDING' WHERE estado = 'PENDIENTE'")
    op.execute("UPDATE replica_almacenamiento SET estado = 'COPYING' WHERE estado = 'COPIANDO'")
    op.execute("UPDATE replica_almacenamiento SET estado = 'VERIFIED' WHERE estado IN ('VERIFICADA', 'DISPONIBLE', 'AVAILABLE')")
    op.execute("UPDATE replica_almacenamiento SET estado = 'RETRYABLE' WHERE estado IN ('FALLO_REINTENTABLE', 'RETRYABLE')")
    op.execute("UPDATE replica_almacenamiento SET estado = 'FAILED' WHERE estado = 'FALLO'")
    op.create_check_constraint(
        "ck_replica_estado",
        "replica_almacenamiento",
        "estado IN ('PENDING', 'COPYING', 'VERIFIED', 'RETRYABLE', 'FAILED', 'MISSING', 'HASH_MISMATCH', 'SIZE_MISMATCH', 'UNAVAILABLE')",
    )


def downgrade():
    op.execute("UPDATE replica_almacenamiento SET estado = 'VERIFICADA' WHERE estado = 'VERIFIED'")
    op.execute("UPDATE replica_almacenamiento SET estado = 'FALLO_REINTENTABLE' WHERE estado IN ('MISSING', 'HASH_MISMATCH', 'SIZE_MISMATCH', 'UNAVAILABLE', 'RETRYABLE')")
    op.execute("UPDATE replica_almacenamiento SET estado = 'FALLO' WHERE estado = 'FAILED'")
    op.execute("ALTER TABLE replica_almacenamiento DROP CONSTRAINT IF EXISTS ck_replica_estado")
    op.create_check_constraint(
        "ck_replica_estado",
        "replica_almacenamiento",
        "estado IN ('PENDIENTE', 'COPIANDO', 'VERIFICADA', 'FALLO_REINTENTABLE', 'FALLO')",
    )
