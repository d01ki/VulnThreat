"""v2 attack-path triage: graph_inputs and analysis_runs (append-only)

Revision ID: 0002_attack_graph
Revises: 0001_initial
Create Date: 2026-11-01
"""
from alembic import op
import sqlalchemy as sa
import tiw.storage.models


revision = '0002_attack_graph'
down_revision = '0001_initial'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('graph_inputs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('seq', sa.Integer(), nullable=False),
    sa.Column('kind', sa.String(length=32), nullable=False),
    sa.Column('source_revision_id', sa.String(length=36), nullable=False),
    sa.Column('content_json', sa.JSON(), nullable=False),
    sa.Column('content_hash', sa.String(length=64), nullable=False),
    sa.Column('synthetic', sa.Boolean(), nullable=False),
    sa.Column('created_at', tiw.storage.models.UTCDateTime(length=32), nullable=False),
    sa.ForeignKeyConstraint(['source_revision_id'], ['source_revisions.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('graph_inputs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_graph_inputs_kind'), ['kind'], unique=False)

    op.create_table('analysis_runs',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('seq', sa.Integer(), nullable=False),
    sa.Column('kind', sa.String(length=24), nullable=False),
    sa.Column('run_key', sa.String(length=200), nullable=False),
    sa.Column('created_at', tiw.storage.models.UTCDateTime(length=32), nullable=False),
    sa.Column('evidence_hash', sa.String(length=64), nullable=False),
    sa.Column('algorithm_version', sa.String(length=64), nullable=False),
    sa.Column('params_json', sa.JSON(), nullable=False),
    sa.Column('result_json', sa.JSON(), nullable=False),
    sa.Column('result_hash', sa.String(length=64), nullable=False),
    sa.Column('previous_id', sa.String(length=36), nullable=True),
    sa.Column('actor', sa.String(length=120), nullable=False),
    sa.ForeignKeyConstraint(['previous_id'], ['analysis_runs.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('analysis_runs', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_analysis_runs_created_at'), ['created_at'], unique=False)
        batch_op.create_index(batch_op.f('ix_analysis_runs_run_key'), ['run_key'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('analysis_runs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_analysis_runs_run_key'))
        batch_op.drop_index(batch_op.f('ix_analysis_runs_created_at'))
    op.drop_table('analysis_runs')
    with op.batch_alter_table('graph_inputs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_graph_inputs_kind'))
    op.drop_table('graph_inputs')
