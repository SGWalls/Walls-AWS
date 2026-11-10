"""
RDS_ExtendedSupport_Query_v0_0_2.py

Queries the AWS Config aggregator for all RDS DB Instances and Aurora DB Clusters.
Engine lifecycle status is determined by comparing each instance's engine/version
against describe_db_major_engine_versions, which is called once from the management
account — no cross-account access required.

Extended Support eligibility logic:
  - 'deprecated' status in describe_db_major_engine_versions means the major version
    has passed standard support end-of-life and is in (or eligible for) Extended Support.
  - SupportsBabelfish / SupportedEngineModes are used to further classify Aurora clusters.
"""

import boto3
import json
import logging
import os
import sys
from datetime import datetime
from botocore.exceptions import ClientError

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'helpers'))
from helper import validate_sso_token, create_logger

logger = logging.getLogger(__name__)

AGGREGATOR_NAME = 'aws-controltower-GuardrailsComplianceAggregator'
OUTPUT_DIR      = r'C:\Users\sgwalls\Documents\AWS_Projects\Exports'

HEADER_FILL  = PatternFill(start_color='1F4E79', end_color='1F4E79', fill_type='solid')
HEADER_FONT  = Font(color='FFFFFF', bold=True)
WARN_FILL    = PatternFill(start_color='FFEB9C', end_color='FFEB9C', fill_type='solid')
WARN_FONT    = Font(color='9C5700', bold=True)
EXPIRED_FILL = PatternFill(start_color='FFC7CE', end_color='FFC7CE', fill_type='solid')
EXPIRED_FONT = Font(color='9C0006', bold=True)


# ---------------------------------------------------------------------------
# Engine version catalogue  (built from describe_db_major_engine_versions)
# ---------------------------------------------------------------------------

# Engines that support RDS Extended Support (open-source only)
ES_ELIGIBLE_ENGINES = {
    'mysql', 'postgres', 'aurora-mysql', 'aurora-postgresql'
}

def build_engine_version_map(rds_client) -> dict:
    """
    Returns a dict keyed by (engine, major_version) with values:
        {
            'standard_support_end':  datetime | None,
            'extended_support_end':  datetime | None,
        }

    Lifecycle dates come from SupportedEngineLifecycles entries:
      - LifecycleSupportName == 'open-source-rds-standard-support'  -> standard end date
      - LifecycleSupportName == 'open-source-rds-extended-support'  -> extended end date
    """
    from datetime import timezone
    version_map = {}
    engines_to_query = list(ES_ELIGIBLE_ENGINES) + ['mariadb', 'oracle-ee', 'sqlserver-se',
                                                      'sqlserver-ee', 'sqlserver-ex', 'sqlserver-web']
    for engine in engines_to_query:
        try:
            paginator = rds_client.get_paginator('describe_db_major_engine_versions')
            for page in paginator.paginate(Engine=engine):
                for ver in page['DBMajorEngineVersions']:
                    std_end = None
                    es_end  = None
                    for lc in ver.get('SupportedEngineLifecycles', []):
                        name     = lc.get('LifecycleSupportName', '')
                        end_date = lc.get('LifecycleSupportEndDate')
                        if name == 'open-source-rds-standard-support':
                            std_end = end_date
                        elif name == 'open-source-rds-extended-support':
                            es_end = end_date
                    version_map[(engine, ver['MajorEngineVersion'])] = {
                        'standard_support_end': std_end,
                        'extended_support_end': es_end,
                    }
        except ClientError as e:
            logger.debug(f"describe_db_major_engine_versions({engine}): {e.response['Error']['Code']}")
    logger.info(f"Engine version catalogue built: {len(version_map)} entries")
    return version_map


def _major_version(engine: str, engine_version: str, version_map: dict) -> str:
    """
    Return the major version string that matches a key in version_map.
    Tries progressively shorter prefixes of engine_version until a match is found.
    e.g. '8.0.32' tries '8.0.32', '8.0', '8' against existing map keys for that engine.
    """
    parts = engine_version.split('.')
    candidates = ['.'.join(parts[:i]) for i in range(len(parts), 0, -1)]
    for candidate in candidates:
        if (engine, candidate) in version_map:
            return candidate
    # No match found — return the two-part prefix as a best guess for logging
    return '.'.join(parts[:2]) if len(parts) >= 2 else parts[0]


def get_es_label(engine: str, engine_version: str, version_map: dict) -> tuple:
    """
    Returns (es_status_label, standard_support_end, extended_support_end).
    Determines status by comparing today against standard_support_end:
      - today > standard_support_end  -> In Extended Support
      - today <= standard_support_end -> Standard Support
    """
    from datetime import timezone
    unknown = ('Unknown', '', '')

    if not engine:
        return unknown

    engine_lower = engine.lower()
    if engine_lower not in ES_ELIGIBLE_ENGINES:
        return ('Not ES Eligible', '', '')

    major = _major_version(engine_lower, engine_version, version_map)
    info  = version_map.get((engine_lower, major))

    if info is None:
        logger.debug(f"No catalogue match: engine='{engine_lower}' version='{engine_version}' derived_major='{major}'")
        logger.debug(f"Available keys for engine: {[k for k in version_map if k[0] == engine_lower]}")
        return (f'Unknown (v{major} not in catalogue)', '', '')

    std_end = info['standard_support_end']
    es_end  = info['extended_support_end']

    std_end_str = std_end.strftime('%Y-%m-%d') if std_end else ''
    es_end_str  = es_end.strftime('%Y-%m-%d')  if es_end  else ''

    if std_end and datetime.now(tz=timezone.utc) > std_end:
        return ('In Extended Support', std_end_str, es_end_str)
    return ('Standard Support', std_end_str, es_end_str)


# ---------------------------------------------------------------------------
# Config aggregator query
# ---------------------------------------------------------------------------

def query_config_aggregator(config_client, resource_type: str) -> list:
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
# Row builders  (Config data only — no cross-account calls)
# ---------------------------------------------------------------------------

def _parse_cfg(item: dict) -> dict:
    cfg = item.get('configuration', {})
    if isinstance(cfg, str):
        try:
            return json.loads(cfg)
        except Exception:
            return {}
    return cfg or {}


def _str_val(field) -> str:
    """Safely extract a string from a field that may be a plain str or {'value': str}."""
    if isinstance(field, dict):
        return str(field.get('value', '') or field.get('address', ''))
    return str(field) if field is not None else ''


def _owner_tag(item: dict) -> str:
    tags = item.get('tags', [])
    if isinstance(tags, list):
        return next((t['value'] for t in tags if t.get('key', '').lower() == 'owner'), '')
    if isinstance(tags, dict):
        return tags.get('Owner', tags.get('owner', ''))
    return ''


def build_instance_rows(config_items: list, version_map: dict) -> list:
    rows = []
    for item in config_items:
        cfg            = _parse_cfg(item)
        engine         = cfg.get('engine', '')
        engine_version = cfg.get('engineVersion', '')
        db_id          = cfg.get('dBInstanceIdentifier', '') or item.get('resourceName', '')
        endpoint       = cfg.get('endpoint') or {}
        dns_name       = endpoint.get('address', '') if isinstance(endpoint, dict) else _str_val(endpoint)
        port           = str(endpoint.get('port', '')) if isinstance(endpoint, dict) else ''

        es_status, std_end, es_end = get_es_label(engine, engine_version, version_map)

        rows.append({
            'Resource Type':          'DB Instance',
            'Account ID':             item.get('accountId', ''),
            'Region':                 item.get('awsRegion', ''),
            'DB Identifier':          db_id,
            'ARN':                    item.get('arn', ''),
            'DNS Name':               dns_name,
            'Port':                   port,
            'Engine':                 engine,
            'Engine Version':         engine_version,
            'DB Instance Class':      cfg.get('dBInstanceClass', ''),
            'Multi-AZ':               cfg.get('multiAZ', ''),
            'Status':                 cfg.get('dBInstanceStatus', ''),
            'Cluster Identifier':     cfg.get('dBClusterIdentifier', ''),
            'ES Status':              es_status,
            'Standard Support End':   std_end,
            'Extended Support End':   es_end,
            'Owner Tag':              _owner_tag(item),
        })
    return rows


def build_cluster_rows(config_items: list, version_map: dict) -> list:
    rows = []
    for item in config_items:
        cfg            = _parse_cfg(item)
        engine         = cfg.get('engine', '')
        engine_version = cfg.get('engineVersion', '')
        cluster_id     = cfg.get('dBClusterIdentifier', '') or item.get('resourceName', '')

        es_status, std_end, es_end = get_es_label(engine, engine_version, version_map)

        rows.append({
            'Resource Type':          'DB Cluster',
            'Account ID':             item.get('accountId', ''),
            'Region':                 item.get('awsRegion', ''),
            'DB Identifier':          cluster_id,
            'ARN':                    item.get('arn', ''),
            'DNS Name':               _str_val(cfg.get('endpoint', '')),
            'Reader Endpoint':        _str_val(cfg.get('readerEndpoint', '')),
            'Engine':                 engine,
            'Engine Version':         engine_version,
            'DB Instance Class':      cfg.get('dBClusterInstanceClass', ''),
            'Multi-AZ':               cfg.get('multiAZ', ''),
            'Status':                 cfg.get('status', ''),
            'Cluster Identifier':     cluster_id,
            'ES Status':              es_status,
            'Standard Support End':   std_end,
            'Extended Support End':   es_end,
            'Owner Tag':              _owner_tag(item),
        })
    return rows


# ---------------------------------------------------------------------------
# Excel export
# ---------------------------------------------------------------------------

INSTANCE_HEADERS = [
    'Resource Type', 'Account ID', 'Region', 'DB Identifier', 'ARN',
    'DNS Name', 'Port', 'Engine', 'Engine Version', 'DB Instance Class',
    'Multi-AZ', 'Status', 'Cluster Identifier',
    'ES Status', 'Standard Support End', 'Extended Support End', 'Owner Tag',
]

CLUSTER_HEADERS = [
    'Resource Type', 'Account ID', 'Region', 'DB Identifier', 'ARN',
    'DNS Name', 'Reader Endpoint', 'Engine', 'Engine Version', 'DB Instance Class',
    'Multi-AZ', 'Status', 'Cluster Identifier',
    'ES Status', 'Standard Support End', 'Extended Support End', 'Owner Tag',
]


def _write_sheet(wb, title: str, headers: list, rows: list):
    ws = wb.create_sheet(title=title)
    ws.append(headers)
    for cell in ws[1]:
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = Alignment(horizontal='center')

    es_col_idx = headers.index('ES Status') + 1 if 'ES Status' in headers else None

    for row_data in rows:
        ws.append([row_data.get(h, '') for h in headers])
        if es_col_idx:
            cell = ws.cell(row=ws.max_row, column=es_col_idx)
            val  = str(cell.value or '')
            if val == 'In Extended Support':
                cell.fill = EXPIRED_FILL
                cell.font = EXPIRED_FONT
            elif val.startswith('Unknown'):
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
    session = boto3.Session(profile_name=profile, region_name='us-west-2')
    validate_sso_token(session)

    rds_client    = session.client('rds',    region_name='us-west-2')
    config_client = session.client('config', region_name='us-west-2')

    logger.info("Building engine version catalogue from describe_db_major_engine_versions...")
    version_map = build_engine_version_map(rds_client)

    logger.info("Querying Config aggregator for DB Instances...")
    instance_items = query_config_aggregator(config_client, 'AWS::RDS::DBInstance')
    logger.info(f"Found {len(instance_items)} DB Instance records")

    logger.info("Querying Config aggregator for DB Clusters...")
    cluster_items = query_config_aggregator(config_client, 'AWS::RDS::DBCluster')
    logger.info(f"Found {len(cluster_items)} DB Cluster records")

    instance_rows = build_instance_rows(instance_items, version_map)
    cluster_rows  = build_cluster_rows(cluster_items,  version_map)

    output_file = os.path.join(OUTPUT_DIR, f'rds_extended_support_{timestamp}.xlsx')
    export_to_excel(instance_rows, cluster_rows, output_file)
    logger.info(f"Done. {len(instance_rows)} instances, {len(cluster_rows)} clusters exported.")


if __name__ == '__main__':
    main()
