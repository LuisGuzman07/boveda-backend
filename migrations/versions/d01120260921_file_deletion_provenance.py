"""CU-11 logical encrypted-file deletion provenance and retention."""

from alembic import op
import sqlalchemy as sa


revision = "d01120260921"
down_revision = "c02020260920"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("archivo", sa.Column("fecha_eliminacion", sa.DateTime(timezone=True), nullable=True))
    op.add_column("archivo", sa.Column("eliminado_por", sa.Uuid(), nullable=True))
    op.add_column("archivo", sa.Column("motivo_eliminacion", sa.String(255), nullable=True))
    op.add_column("archivo", sa.Column("solicitud_eliminacion_id", sa.String(100), nullable=True))
    op.add_column("archivo", sa.Column("estado_limpieza", sa.String(30), nullable=False, server_default="RETENCION"))
    op.create_foreign_key("fk_archivo_eliminado_por", "archivo", "usuario", ["eliminado_por"], ["id_usuario"], ondelete="SET NULL")
    op.create_check_constraint("ck_archivo_estado_limpieza", "archivo", "estado_limpieza IN ('RETENCION', 'REINTENTO_LIMPIEZA', 'LIMPIADO')")


def downgrade():
    op.drop_constraint("ck_archivo_estado_limpieza", "archivo", type_="check")
    op.drop_constraint("fk_archivo_eliminado_por", "archivo", type_="foreignkey")
    op.drop_column("archivo", "estado_limpieza")
    op.drop_column("archivo", "solicitud_eliminacion_id")
    op.drop_column("archivo", "motivo_eliminacion")
    op.drop_column("archivo", "eliminado_por")
    op.drop_column("archivo", "fecha_eliminacion")
