"""GitHub App Auto-PR Remediation migration

Revision ID: 002_github_app_remediation
Revises: 001_initial_db_and_auth
Create Date: 2026-09-26 12:10:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '002_github_app_remediation'
down_revision = '001_initial_db_and_auth'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add github_installation_id to organizations
    op.add_column('organizations', sa.Column('github_installation_id', sa.String(length=64), nullable=True))

    # 2. Add PR tracking columns to findings
    op.add_column('findings', sa.Column('pr_url', sa.String(length=512), nullable=True))
    op.add_column('findings', sa.Column('pr_status', sa.String(length=32), nullable=True))
    op.add_column('findings', sa.Column('pr_branch', sa.String(length=128), nullable=True))

    # 3. Create domain_repo_mappings table
    op.create_table(
        'domain_repo_mappings',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('org_id', sa.String(length=64), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('repo_full_name', sa.String(length=255), nullable=False),
        sa.Column('default_branch', sa.String(length=64), nullable=True, server_default='main'),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_domain_repo_mappings_id'), 'domain_repo_mappings', ['id'], unique=False)
    op.create_index(op.f('ix_domain_repo_mappings_org_id'), 'domain_repo_mappings', ['org_id'], unique=False)
    op.create_index(op.f('ix_domain_repo_mappings_domain'), 'domain_repo_mappings', ['domain'], unique=False)


def downgrade() -> None:
    op.drop_table('domain_repo_mappings')
    op.drop_column('findings', 'pr_branch')
    op.drop_column('findings', 'pr_status')
    op.drop_column('findings', 'pr_url')
    op.drop_column('organizations', 'github_installation_id')
