"""Initial database migration: organizations, users, api_keys, scans, findings

Revision ID: 001_initial_db_and_auth
Revises: 
Create Date: 2026-09-26 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '001_initial_db_and_auth'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. organizations
    op.create_table(
        'organizations',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_organizations_id'), 'organizations', ['id'], unique=False)

    # 2. users
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('org_id', sa.String(length=64), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=True),
        sa.Column('role', sa.String(length=16), nullable=True, server_default='member'),
        sa.Column('hashed_password', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=False)
    op.create_index(op.f('ix_users_org_id'), 'users', ['org_id'], unique=False)

    # 3. api_keys
    op.create_table(
        'api_keys',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('org_id', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.String(length=64), nullable=True),
        sa.Column('key_hash', sa.String(length=128), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('role', sa.String(length=16), nullable=True, server_default='member'),
        sa.Column('is_active', sa.Boolean(), nullable=True, server_default='true'),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_used_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_api_keys_id'), 'api_keys', ['id'], unique=False)
    op.create_index(op.f('ix_api_keys_key_hash'), 'api_keys', ['key_hash'], unique=False)
    op.create_index(op.f('ix_api_keys_org_id'), 'api_keys', ['org_id'], unique=False)

    # 4. scans
    op.create_table(
        'scans',
        sa.Column('scan_id', sa.String(length=64), nullable=False),
        sa.Column('org_id', sa.String(length=64), nullable=True),
        sa.Column('target_url', sa.String(length=1024), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=True, server_default='QUEUED'),
        sa.Column('current_step', sa.String(length=255), nullable=True),
        sa.Column('progress', sa.Integer(), nullable=True, server_default='0'),
        sa.Column('started_at', sa.String(length=64), nullable=False),
        sa.Column('completed_at', sa.String(length=64), nullable=True),
        sa.Column('score', sa.Integer(), nullable=True, server_default='100'),
        sa.Column('grade', sa.String(length=8), nullable=True, server_default='A+'),
        sa.Column('findings_summary', sa.JSON(), nullable=True),
        sa.Column('ai_summary', sa.Text(), nullable=True),
        sa.Column('executive_overview', sa.Text(), nullable=True),
        sa.Column('is_domain_verified', sa.Boolean(), nullable=True, server_default='false'),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('scan_type', sa.String(length=32), nullable=True, server_default='passive'),
        sa.Column('framework_hint', sa.String(length=64), nullable=True),
        sa.Column('repo_full_name', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['org_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('scan_id')
    )
    op.create_index(op.f('ix_scans_scan_id'), 'scans', ['scan_id'], unique=False)
    op.create_index(op.f('ix_scans_domain'), 'scans', ['domain'], unique=False)
    op.create_index(op.f('ix_scans_status'), 'scans', ['status'], unique=False)
    op.create_index(op.f('ix_scans_org_id'), 'scans', ['org_id'], unique=False)

    # 5. findings
    op.create_table(
        'findings',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('finding_id', sa.String(length=128), nullable=False),
        sa.Column('scan_id', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('category', sa.String(length=128), nullable=False),
        sa.Column('severity', sa.String(length=16), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=True, server_default='0.0'),
        sa.Column('cvss_vector', sa.String(length=128), nullable=True),
        sa.Column('cwe_id', sa.String(length=32), nullable=True),
        sa.Column('owasp_category', sa.String(length=128), nullable=True),
        sa.Column('confidence', sa.String(length=32), nullable=True, server_default='CERTAIN'),
        sa.Column('endpoint', sa.String(length=1024), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('request_proof', sa.Text(), nullable=True),
        sa.Column('response_proof', sa.Text(), nullable=True),
        sa.Column('impact', sa.Text(), nullable=True),
        sa.Column('remediation_summary', sa.Text(), nullable=True),
        sa.Column('remediation_effort', sa.String(length=16), nullable=True, server_default='LOW'),
        sa.Column('remediation_code', sa.JSON(), nullable=True),
        sa.Column('references_list', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.scan_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_findings_id'), 'findings', ['id'], unique=False)
    op.create_index(op.f('ix_findings_finding_id'), 'findings', ['finding_id'], unique=False)
    op.create_index(op.f('ix_findings_scan_id'), 'findings', ['scan_id'], unique=False)
    op.create_index(op.f('ix_findings_severity'), 'findings', ['severity'], unique=False)
    op.create_index(op.f('ix_findings_cwe_id'), 'findings', ['cwe_id'], unique=False)


def downgrade() -> None:
    op.drop_table('findings')
    op.drop_table('scans')
    op.drop_table('api_keys')
    op.drop_table('users')
    op.drop_table('organizations')
