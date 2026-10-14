"""Compliance Reports and audit metadata migration

Revision ID: 004_compliance_and_reporting
Revises: 003_cicd_continuous_scanning
Create Date: 2026-09-26 12:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '004_compliance_and_reporting'
down_revision = '003_cicd_continuous_scanning'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Index owasp_category for fast compliance mapping aggregations
    op.create_index(op.f('ix_findings_owasp_category'), 'findings', ['owasp_category'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_findings_owasp_category'), table_name='findings')
