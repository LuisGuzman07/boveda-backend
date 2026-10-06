"""drop replica_almacenamiento_clave_objeto_key unique constraint"""

from alembic import op

revision = "i02420261006"
down_revision = "h02320260921"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("ALTER TABLE replica_almacenamiento DROP CONSTRAINT IF EXISTS replica_almacenamiento_clave_objeto_key")


def downgrade():
    op.create_unique_constraint(
        "replica_almacenamiento_clave_objeto_key",
        "replica_almacenamiento",
        ["clave_objeto"],
    )
