"""CU-21 append-only audit chain and CU-22 local anomaly analysis."""

from alembic import op
import sqlalchemy as sa
import hashlib
import json
from datetime import timezone


revision = "g02120260921"
down_revision = "f01820260921"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("evento_auditoria", sa.Column("chain_sequence", sa.Integer(), nullable=True))
    op.add_column("evento_auditoria", sa.Column("previous_hash", sa.String(64), nullable=True))
    op.add_column("evento_auditoria", sa.Column("event_hash", sa.String(64), nullable=True))
    op.add_column("evento_auditoria", sa.Column("schema_version", sa.Integer(), nullable=False, server_default="1"))
    op.execute("CREATE SEQUENCE evento_auditoria_chain_seq")
    bind = op.get_bind()
    rows = bind.execute(sa.text("""
        SELECT id_evento, id_usuario, id_dispositivo, accion, tipo_evento, resultado,
               recurso_id, recurso_tipo, direccion_ip, user_agent, detalles, fecha_evento
        FROM evento_auditoria ORDER BY fecha_evento, id_evento
    """)).mappings().all()
    previous_hash = "0" * 64
    for sequence, row in enumerate(rows, start=1):
        occurred = row["fecha_evento"].astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        payload = {
            "schema_version": 1, "sequence": sequence, "previous_hash": previous_hash,
            "id_evento": str(row["id_evento"]), "id_usuario": str(row["id_usuario"]) if row["id_usuario"] else None,
            "id_dispositivo": str(row["id_dispositivo"]) if row["id_dispositivo"] else None,
            "accion": row["accion"], "tipo_evento": row["tipo_evento"], "resultado": row["resultado"],
            "recurso_id": row["recurso_id"], "recurso_tipo": row["recurso_tipo"],
            "direccion_ip": row["direccion_ip"], "user_agent": row["user_agent"],
            "detalles": row["detalles"] or {}, "fecha_evento": occurred,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str).encode("utf-8")).hexdigest()
        bind.execute(sa.text("""
            UPDATE evento_auditoria SET chain_sequence = :sequence, previous_hash = :previous_hash,
            event_hash = :event_hash, schema_version = 1 WHERE id_evento = :id_evento
        """), {"sequence": sequence, "previous_hash": previous_hash, "event_hash": digest, "id_evento": row["id_evento"]})
        previous_hash = digest
    if rows:
        bind.execute(sa.text("SELECT setval('evento_auditoria_chain_seq', :value, true)"), {"value": len(rows)})
    op.alter_column("evento_auditoria", "chain_sequence", nullable=False)
    op.alter_column("evento_auditoria", "previous_hash", nullable=False)
    op.alter_column("evento_auditoria", "event_hash", nullable=False)
    op.create_index("ix_evento_auditoria_chain_sequence", "evento_auditoria", ["chain_sequence"], unique=True)
    op.create_unique_constraint("uq_evento_auditoria_event_hash", "evento_auditoria", ["event_hash"])
    op.execute("""
        CREATE OR REPLACE FUNCTION reject_evento_auditoria_mutation()
        RETURNS trigger AS $$
        BEGIN
          RAISE EXCEPTION 'evento_auditoria is append-only' USING ERRCODE = 'integrity_constraint_violation';
        END;
        $$ LANGUAGE plpgsql;
    """)
    op.execute("""
        CREATE TRIGGER evento_auditoria_append_only
        BEFORE UPDATE OR DELETE ON evento_auditoria
        FOR EACH ROW EXECUTE FUNCTION reject_evento_auditoria_mutation();
    """)
    # The trigger protects even the table owner. Revoking public mutation is a
    # second layer that is safe for deployments with separate application roles.
    op.execute("REVOKE UPDATE, DELETE ON evento_auditoria FROM PUBLIC")
    op.create_table(
        "analisis_anomalia",
        sa.Column("id_analisis", sa.Uuid(), primary_key=True),
        sa.Column("id_solicitante", sa.Uuid(), sa.ForeignKey("usuario.id_usuario"), nullable=False),
        sa.Column("estado", sa.String(20), nullable=False),
        sa.Column("model_version", sa.String(50), nullable=False),
        sa.Column("random_state", sa.Integer(), nullable=False),
        sa.Column("feature_schema_version", sa.String(50), nullable=False),
        sa.Column("configuracion", sa.JSON(), nullable=False),
        sa.Column("secuencia_inicio", sa.Integer(), nullable=True),
        sa.Column("secuencia_fin", sa.Integer(), nullable=True),
        sa.Column("total_eventos", sa.Integer(), nullable=False),
        sa.Column("estado_integridad", sa.String(20), nullable=False),
        sa.Column("motivo", sa.Text(), nullable=True),
        sa.Column("fecha_creacion", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_table(
        "hallazgo_anomalia",
        sa.Column("id_hallazgo", sa.Uuid(), primary_key=True),
        sa.Column("id_analisis", sa.Uuid(), sa.ForeignKey("analisis_anomalia.id_analisis", ondelete="CASCADE"), nullable=False),
        sa.Column("id_evento", sa.Uuid(), sa.ForeignKey("evento_auditoria.id_evento"), nullable=False),
        sa.Column("secuencia_evento", sa.Integer(), nullable=False),
        sa.Column("decision_score", sa.Float(), nullable=False),
        sa.Column("etiqueta", sa.String(20), nullable=False),
        sa.Column("explicacion", sa.Text(), nullable=False),
    )
    op.create_index("ix_hallazgo_anomalia_analisis", "hallazgo_anomalia", ["id_analisis"])
    op.create_index("ix_hallazgo_anomalia_evento", "hallazgo_anomalia", ["id_evento"])


def downgrade():
    op.drop_index("ix_hallazgo_anomalia_evento", table_name="hallazgo_anomalia")
    op.drop_index("ix_hallazgo_anomalia_analisis", table_name="hallazgo_anomalia")
    op.drop_table("hallazgo_anomalia")
    op.drop_table("analisis_anomalia")
    op.execute("DROP TRIGGER evento_auditoria_append_only ON evento_auditoria")
    op.execute("DROP FUNCTION reject_evento_auditoria_mutation()")
    op.execute("DROP SEQUENCE evento_auditoria_chain_seq")
    op.drop_constraint("uq_evento_auditoria_event_hash", "evento_auditoria", type_="unique")
    op.drop_index("ix_evento_auditoria_chain_sequence", table_name="evento_auditoria")
    op.drop_column("evento_auditoria", "schema_version")
    op.drop_column("evento_auditoria", "event_hash")
    op.drop_column("evento_auditoria", "previous_hash")
    op.drop_column("evento_auditoria", "chain_sequence")
