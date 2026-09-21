"""CU-23 safe aggregate compliance reports."""

from alembic import op
import sqlalchemy as sa


revision = "h02320260921"
down_revision = "g02120260921"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "reporte_cumplimiento",
        sa.Column("id_reporte", sa.Uuid(), primary_key=True),
        sa.Column("id_solicitante", sa.Uuid(), sa.ForeignKey("usuario.id_usuario"), nullable=False),
        sa.Column("version", sa.String(30), nullable=False),
        sa.Column("filtros", sa.JSON(), nullable=False),
        sa.Column("resumen", sa.JSON(), nullable=False),
        sa.Column("fecha_generacion", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_reporte_cumplimiento_solicitante", "reporte_cumplimiento", ["id_solicitante"])


def downgrade():
    op.drop_index("ix_reporte_cumplimiento_solicitante", table_name="reporte_cumplimiento")
    op.drop_table("reporte_cumplimiento")
