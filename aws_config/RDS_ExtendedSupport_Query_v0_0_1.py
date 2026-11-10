"""
RDS_ExtendedSupport_Query_v0_0_1.py

Queries the AWS Config aggregator for all RDS DB Instances and Aurora DB Clusters,
enriches results with EngineLifecycleSupport from the RDS API, and exports to xlsx.

Extended Support end dates are sourced from:
  https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/extended-support-charges.html
"""

import boto3
import json
import logging
import os
import sys
from datetime import date, datetime
from botocore.exceptions import ClientError

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, PatternFill
from openpyxl.utils import get_column_letter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'helpers'))
from helper import validate_sso_token, create_logger

logger = logging.getLogger(__name__)

AGGREGATOR_NAME = 'aws-controltower-GuardrailsComplianceAggregator'
ROLE_NAME       = 'AWSControlTowerExecution'
SESSION_NAME    = 'RDSExtendedSupportQuery'
OUTPUT_DIR      = os.path.expanduser('~/Documents')

# ---------------------------------------------------------------------------
# Known RDS Extended Support end dates  (engine -> major_version -> end_date)
# Source: AWS RDS Extended Support documentation
# ---------------------------------------------------------------------------
EXTENDED_SUPPORT_END_DATES = {
    'mysql': {
        '5.7': date(2025, 2, 29),   # ES Year 1 ends; Year 2 ends 2026-02-28
        '8.0': date(2026, 4, 30),
    },
    'postgres': {
        '11': date(2024, 2, 29),
        '12': date(2025, 2, 28),
        '13': date(2026, 2, 28),
        '14': date(2027, 2, 28),
    },
    'aurora-mysql': {
        '5.7': date(2025, 2, 29),
        '8.0': date(2026, 4, 30),
    },
    'aurora-postgresql': {
        '11': date(2024, 2, 29),
        '12': date(2025, 2, 28),
        '13': date(2026, 2, 28),
        '14': date(2027, 2, 28),
    },
}

WARN_DAYS = 180  # flag instances within this many days of ES end date

HEADER_FILL = PatternFill(start_color='1F4E79', end_color='1F4E79', fill_type='solid')
HEADER_FONT = Font(color='FFFFFF', bold=True)
WARN_FILL   = PatternFill(start_color='FFEB9C', end_color='FFEB9C', fill_type='solid')
WARN_FONT   = Font(color='9C5700', bold=True)
EXPIRED_FILL = PatternFill(start_color='FFC7CE', end_color='FFC7CE', fill_type='solid')
EXPIRED_FONT = Font(color='9C0006', bold=True)


# ---------------------------------------------------------------------------
# Extended support helpers
# ---------------------------------------------------------------------------

def _major_version(engine_version: str) -> str:
    """Return major.minor version string (e.g. '8.0' from '8.0.32')."""
    parts = engine_version.split('.')
    return '.'.join(parts[:2]) if len(parts) >= 2 else engine_version


def get_es_end_date(engine: str, engine_version: str):
    """Return the known ES end date for this engine/version, or None."""
    engine_lower = engine.lower()
    major = _major_version(engine_version)
    for eng_key, versions in EXTENDED_SUPPORT_END_DATES.items():
        if eng_key in engine_lower:
            return versions.get(major)
    return None


def es_status_label(end_date) -> str:
    if end_date is None:
        return ''
    today = date.today()
    delta = (end_date - today).days
    if delta < 0:
        return f'EXPIRED ({end_date})'
    if delta <= WARN_DAYS:
        return f'EXPIRING SOON ({end_date})'
    return f'Active until {end_date}'


# ---------------------------------------------------------------------------
# Config aggregator query
# ---------------------------------------------------------------------------

def query_config_aggregator(config_client, resource_type: str) -> list:
    """Run a paginated Config aggregator query for the given resource type."""
    query = f"""
        SELECT
            accountId,
            awsRegion,
            resourceId,
            resourceName,
            arn,
            configuration,
            tags
        WHERE
            resourceType = '{resource_type}'
    """
    results = []
    try:
        paginator = config_client.get_paginator('select_aggregate_resource_config')
        for page in paginator.paginate(
            ConfigurationAggregatorName=AGGREGATOR_NAME,
            Expression=query
        ):
            for item in page['Results']:
                results.append(json.loads(item))
    except ClientError as e:
        logger.error(f"Config query failed for {resource_type}: {e.response['Error']}")
    return results


# ---------------------------------------------------------------------------
# RDS API enrichment  (EngineLifecycleSupport lives here, not in Config)
# ---------------------------------------------------------------------------

def _assume_role(sts_client, account_id: str) -> dict:
    resp = sts_client.assume_role(
        RoleArn=f'arn:aws:iam::{account_id}:role/{ROLE_NAME}',
        RoleSessionName=SESSION_NAME,
        DurationSeconds=3600,
    )
    return resp['Credentials']


def _rds_client(credentials: dict, region: str):
    return boto3.client(
        'rds',
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken'],
        region_name=region,
    )


def get_instance_lifecycle_support(rds, db_instance_id: str) -> str:
    """Return EngineLifecycleSupport for a DB instance ('open-source-rds-extended-support', etc.)."""
    try:
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)
        return resp['DBInstances'][0].get('EngineLifecycleSupport', 'N/A')
    except Exception as e:
        logger.debug(f"describe_db_instances({db_instance_id}): {e}")
        return 'N/A'


def get_cluster_lifecycle_support(rds, db_cluster_id: str) -> str:
    """Return EngineLifecycleSupport for a DB cluster."""
    try:
        resp = rds.describe_db_clusters(DBClusterIdentifier=db_cluster_id)
        return resp['DBClusters'][0].get('EngineLifecycleSupport', 'N/A')
    except Exception as e:
        logger.debug(f"describe_db_clusters({db_cluster_id}): {e}")
        return 'N/A'


# ---------------------------------------------------------------------------
# Row builders
# ---------------------------------------------------------------------------

def build_instance_rows(config_items: list, session) -> list:
    """Build one row per DB instance, enriched with RDS API data."""
    # Group by (account, region) to minimise assume-role calls
    grouped: dict[tuple, list] = {}
    for item in config_items:
        key = (item['accountId'], item['awsRegion'])
        grouped.setdefault(key, []).append(item)

    caller_account = session.client('sts').get_caller_identity()['Account']
    sts = session.client('sts')
    rows = []

    for (account_id, region), items in grouped.items():
        try:
            if account_id == caller_account:
                creds = session.get_credentials().get_frozen_credentials()
                credentials = {
                    'AccessKeyId': creds.access_key,
                    'SecretAccessKey': creds.secret_key,
                    'SessionToken': creds.token,
                }
            else:
                credentials = _assume_role(sts, account_id)
            rds = _rds_client(credentials, region)
        except Exception as e:
            logger.warning(f"Cannot get credentials for {account_id}/{region}: {e}")
            credentials = None
            rds = None

        for item in items:
            cfg = item.get('configuration', {})
            if isinstance(cfg, str):
                try:
                    cfg = json.loads(cfg)
                except Exception:
                    cfg = {}

            engine         = cfg.get('engine', '')
            engine_version = cfg.get('engineVersion', '')
            db_id          = cfg.get('dBInstanceIdentifier', '') or item.get('resourceName', '')
            endpoint       = cfg.get('endpoint', {}) or {}
            dns_name       = endpoint.get('address', '')
            port           = endpoint.get('port', '')

            lifecycle = get_instance_lifecycle_support(rds, db_id) if rds else 'N/A'
            es_end    = get_es_end_date(engine, engine_version)

            tags = item.get('tags', [])
            owner_tag = next((t['value'] for t in tags if t.get('key', '').lower() == 'owner'), '')

            rows.append({
                'Resource Type':            'DB Instance',
                'Account ID':               account_id,
                'Region':                   region,
                'DB Identifier':            db_id,
                'ARN':                      item.get('arn', ''),
                'DNS Name':                 dns_name,
                'Port':                     port,
                'Engine':                   engine,
                'Engine Version':           engine_version,
                'DB Instance Class':        cfg.get('dBInstanceClass', ''),
                'Multi-AZ':                 cfg.get('multiAZ', ''),
                'Status':                   cfg.get('dBInstanceStatus', ''),
                'Cluster Identifier':       cfg.get('dBClusterIdentifier', ''),
                'Engine Lifecycle Support': lifecycle,
                'ES End Date Status':       es_status_label(es_end),
                'Owner Tag':                owner_tag,
            })

    return rows


def build_cluster_rows(config_items: list, session) -> list:
    """Build one row per Aurora DB cluster, enriched with RDS API data."""
    grouped: dict[tuple, list] = {}
    for item in config_items:
        key = (item['accountId'], item['awsRegion'])
        grouped.setdefault(key, []).append(item)

    caller_account = session.client('sts').get_caller_identity()['Account']
    sts = session.client('sts')
    rows = []

    for (account_id, region), items in grouped.items():
        try:
            if account_id == caller_account:
                creds = session.get_credentials().get_frozen_credentials()
                credentials = {
                    'AccessKeyId': creds.access_key,
                    'SecretAccessKey': creds.secret_key,
                    'SessionToken': creds.token,
                }
            else:
                credentials = _assume_role(sts, account_id)
            rds = _rds_client(credentials, region)
        except Exception as e:
            logger.warning(f"Cannot get credentials for {account_id}/{region}: {e}")
            rds = None

        for item in items:
            cfg = item.get('configuration', {})
            if isinstance(cfg, str):
                try:
                    cfg = json.loads(cfg)
                except Exception:
                    cfg = {}

            engine         = cfg.get('engine', '')
            engine_version = cfg.get('engineVersion', '')
            cluster_id     = cfg.get('dBClusterIdentifier', '') or item.get('resourceName', '')
            endpoint       = cfg.get('endpoint', '')
            reader_ep      = cfg.get('readerEndpoint', '')

            lifecycle = get_cluster_lifecycle_support(rds, cluster_id) if rds else 'N/A'
            es_end    = get_es_end_date(engine, engine_version)

            tags = item.get('tags', [])
            owner_tag = next((t['value'] for t in tags if t.get('key', '').lower() == 'owner'), '')

            rows.append({
                'Resource Type':            'DB Cluster',
                'Account ID':               account_id,
                'Region':                   region,
                'DB Identifier':            cluster_id,
                'ARN':                      item.get('arn', ''),
                'DNS Name':                 endpoint,
                'Reader Endpoint':          reader_ep,
                'Engine':                   engine,
                'Engine Version':           engine_version,
                'DB Instance Class':        cfg.get('dBClusterInstanceClass', ''),
                'Multi-AZ':                 cfg.get('multiAZ', ''),
                'Status':                   cfg.get('status', ''),
                'Cluster Identifier':       cluster_id,
                'Engine Lifecycle Support': lifecycle,
                'ES End Date Status':       es_status_label(es_end),
                'Owner Tag':                owner_tag,
            })

    return rows


# ---------------------------------------------------------------------------
# Excel export
# ---------------------------------------------------------------------------

INSTANCE_HEADERS = [
    'Resource Type', 'Account ID', 'Region', 'DB Identifier', 'ARN',
    'DNS Name', 'Port', 'Engine', 'Engine Version', 'DB Instance Class',
    'Multi-AZ', 'Status', 'Cluster Identifier',
    'Engine Lifecycle Support', 'ES End Date Status', 'Owner Tag',
]

CLUSTER_HEADERS = [
    'Resource Type', 'Account ID', 'Region', 'DB Identifier', 'ARN',
    'DNS Name', 'Reader Endpoint', 'Engine', 'Engine Version', 'DB Instance Class',
    'Multi-AZ', 'Status', 'Cluster Identifier',
    'Engine Lifecycle Support', 'ES End Date Status', 'Owner Tag',
]


def _write_sheet(wb, title: str, headers: list, rows: list):
    ws = wb.create_sheet(title=title)
    ws.append(headers)
    for cell in ws[1]:
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = Alignment(horizontal='center')

    es_col_idx = headers.index('ES End Date Status') + 1 if 'ES End Date Status' in headers else None

    for row_data in rows:
        row_values = [row_data.get(h, '') for h in headers]
        ws.append(row_values)
        if es_col_idx:
            cell = ws.cell(row=ws.max_row, column=es_col_idx)
            val = str(cell.value or '')
            if val.startswith('EXPIRED'):
                cell.fill = EXPIRED_FILL
                cell.font = EXPIRED_FONT
            elif val.startswith('EXPIRING SOON'):
                cell.fill = WARN_FILL
                cell.font = WARN_FONT

    for col_cells in ws.columns:
        width = max(len(str(c.value or '')) for c in col_cells) + 4
        ws.column_dimensions[get_column_letter(col_cells[0].column)].width = min(width, 80)


def export_to_excel(instance_rows: list, cluster_rows: list, output_path: str):
    wb = openpyxl.Workbook()
    wb.remove(wb.active)
    _write_sheet(wb, 'RDS Instances', INSTANCE_HEADERS, instance_rows)
    _write_sheet(wb, 'Aurora Clusters', CLUSTER_HEADERS, cluster_rows)
    wb.save(output_path)
    logger.info(f"Results saved to: {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    create_logger(__name__, OUTPUT_DIR, f'rds_extended_support_{timestamp}.log')

    profile = input("AWS SSO profile name [ct_master]: ").strip() or 'ct_master'
    session = boto3.Session(profile_name=profile, region_name='us-east-1')
    validate_sso_token(session)

    config_client = session.client('config', region_name='us-east-1')

    logger.info("Querying Config aggregator for DB Instances...")
    instance_items = query_config_aggregator(config_client, 'AWS::RDS::DBInstance')
    logger.info(f"Found {len(instance_items)} DB Instance records in Config")

    logger.info("Querying Config aggregator for DB Clusters...")
    cluster_items = query_config_aggregator(config_client, 'AWS::RDS::DBCluster')
    logger.info(f"Found {len(cluster_items)} DB Cluster records in Config")

    logger.info("Enriching DB Instance data from RDS API...")
    instance_rows = build_instance_rows(instance_items, session)

    logger.info("Enriching DB Cluster data from RDS API...")
    cluster_rows = build_cluster_rows(cluster_items, session)

    output_file = os.path.join(OUTPUT_DIR, f'rds_extended_support_{timestamp}.xlsx')
    export_to_excel(instance_rows, cluster_rows, output_file)
    logger.info(f"Done. {len(instance_rows)} instances, {len(cluster_rows)} clusters exported.")


if __name__ == '__main__':
    main()
