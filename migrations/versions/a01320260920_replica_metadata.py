"""CU-13/CU-14 replica lifecycle metadata and optional S3 support."""

from alembic import op
import sqlalchemy as sa


revision = "a01320260920"
down_revision = ("e00820260920", "f2a1b3c4d5e6")
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("replica_almacenamiento", sa.Column("version_id", sa.String(255), nullable=True))
    op.add_column("replica_almacenamiento", sa.Column("tamano_esperado", sa.Integer(), nullable=True))
    op.add_column("replica_almacenamiento", sa.Column("intentos", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("replica_almacenamiento", sa.Column("ultimo_error", sa.String(500), nullable=True))
    op.execute(
        "UPDATE replica_almacenamiento SET tamano_esperado = "
        "(SELECT tamano_cifrado - 16 FROM version_archivo "
        "WHERE version_archivo.id_version_archivo = replica_almacenamiento.id_version_archivo) "
        "WHERE tamano_esperado IS NULL"
    )
    op.execute("UPDATE replica_almacenamiento SET estado = 'VERIFICADA' WHERE estado = 'DISPONIBLE'")
    op.alter_column("replica_almacenamiento", "tamano_esperado", nullable=False)
    op.drop_constraint("uq_replica_version_proveedor", "replica_almacenamiento", type_="unique")
    op.create_unique_constraint(
        "uq_replica_version_proveedor", "replica_almacenamiento", ["id_version_archivo", "proveedor"]
    )
    op.create_unique_constraint(
        "uq_replica_proveedor_objeto", "replica_almacenamiento", ["proveedor", "clave_objeto"]
    )


def downgrade():
    op.drop_constraint("uq_replica_proveedor_objeto", "replica_almacenamiento", type_="unique")
    op.drop_constraint("uq_replica_version_proveedor", "replica_almacenamiento", type_="unique")
    op.create_unique_constraint(
        "uq_replica_version_proveedor", "replica_almacenamiento", ["id_version_archivo", "proveedor"]
    )
    op.drop_column("replica_almacenamiento", "ultimo_error")
    op.drop_column("replica_almacenamiento", "intentos")
    op.drop_column("replica_almacenamiento", "tamano_esperado")
    op.drop_column("replica_almacenamiento", "version_id")
