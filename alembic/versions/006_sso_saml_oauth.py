"""Enterprise SSO SAML and OAuth migration

Revision ID: 006_sso_saml_oauth
Revises: 005_dashboard_domains
Create Date: 2026-09-26 12:50:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '006_sso_saml_oauth'
down_revision = '005_dashboard_domains'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('organizations', sa.Column('saml_metadata', sa.Text(), nullable=True))
    op.add_column('organizations', sa.Column('sso_provider', sa.String(length=32), nullable=True))
    op.add_column('organizations', sa.Column('sso_client_id', sa.String(length=255), nullable=True))
    op.add_column('organizations', sa.Column('sso_client_secret_encrypted', sa.Text(), nullable=True))
    op.add_column('organizations', sa.Column('sso_discovery_url', sa.String(length=512), nullable=True))


def downgrade() -> None:
    op.drop_column('organizations', 'sso_discovery_url')
    op.drop_column('organizations', 'sso_client_secret_encrypted')
    op.drop_column('organizations', 'sso_client_id')
    op.drop_column('organizations', 'sso_provider')
    op.drop_column('organizations', 'saml_metadata')
