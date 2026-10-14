"""CI/CD Continuous Scanning and Notifications migration

Revision ID: 003_cicd_continuous_scanning
Revises: 002_github_app_remediation
Create Date: 2026-09-26 12:20:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '003_cicd_continuous_scanning'
down_revision = '002_github_app_remediation'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add notification settings to organizations
    op.add_column('organizations', sa.Column('slack_webhook_url', sa.String(length=512), nullable=True))
    op.add_column('organizations', sa.Column('notify_on_new_findings', sa.Boolean(), nullable=True, server_default='true'))
    op.add_column('organizations', sa.Column('min_severity_to_notify', sa.String(length=16), nullable=True, server_default='HIGH'))

    # 2. Create webhook_endpoints table
    op.create_table(
        'webhook_endpoints',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('org_id', sa.String(length=64), nullable=False),
        sa.Column('secret_token', sa.String(length=128), nullable=False),
        sa.Column('provider', sa.String(length=32), nullable=True, server_default='generic'),
        sa.Column('target_domain', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_webhook_endpoints_id'), 'webhook_endpoints', ['id'], unique=False)
    op.create_index(op.f('ix_webhook_endpoints_org_id'), 'webhook_endpoints', ['org_id'], unique=False)


def downgrade() -> None:
    op.drop_table('webhook_endpoints')
    op.drop_column('organizations', 'min_severity_to_notify')
    op.drop_column('organizations', 'notify_on_new_findings')
    op.drop_column('organizations', 'slack_webhook_url')
