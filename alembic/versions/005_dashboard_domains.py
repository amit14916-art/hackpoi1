"""Org-Level Dashboard and Domains migration

Revision ID: 005_dashboard_domains
Revises: 004_compliance_and_reporting
Create Date: 2026-09-26 12:40:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '005_dashboard_domains'
down_revision = '004_compliance_and_reporting'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'domains',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('org_id', sa.String(length=64), nullable=False),
        sa.Column('url', sa.String(length=1024), nullable=False),
        sa.Column('domain_name', sa.String(length=255), nullable=False),
        sa.Column('is_domain_verified', sa.Boolean(), nullable=True, server_default='false'),
        sa.Column('last_scan_id', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['last_scan_id'], ['scans.scan_id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_domains_id'), 'domains', ['id'], unique=False)
    op.create_index(op.f('ix_domains_org_id'), 'domains', ['org_id'], unique=False)
    op.create_index(op.f('ix_domains_domain_name'), 'domains', ['domain_name'], unique=False)


def downgrade() -> None:
    op.drop_table('domains')
