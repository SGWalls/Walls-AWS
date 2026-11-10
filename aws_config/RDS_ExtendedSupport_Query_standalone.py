"""
RDS_ExtendedSupport_Query_standalone.py

PURPOSE
-------
Queries an AWS Config multi-account aggregator for all RDS DB Instances and
Aurora DB Clusters across every account/region it covers, then classifies each
resource's engine version against the official RDS lifecycle dates to determine
whether it is currently in (or approaching) Extended Support.

HOW IT WORKS
------------
1. The script calls describe_db_major_engine_versions once against the account
   whose credentials you supply.  This builds a local catalogue of every engine
   major version and its Standard / Extended Support end dates.

2. It then queries the Config aggregator using a SQL-like expression.  Because
   the aggregator already holds a snapshot of every member account's resources,
   no cross-account role assumptions are needed.

3. Each resource record is matched against the catalogue and assigned one of:
     - "Standard Support"            : still within the standard support window
     - "In Extended Support"         : standard support has ended; extra charges apply
     - "Not ES Eligible"             : engine type (e.g. SQL Server) is not subject to
                                       the open-source Extended Support programme
     - "Unknown (vX.Y not in catalogue)" : version could not be matched; investigate

4. Results are written to a timestamped Excel workbook with two sheets:
     - RDS Instances
     - Aurora Clusters
   Rows in Extended Support are highlighted red; unmatched versions are amber.

PREREQUISITES
-------------
  - Python 3.8+
  - pip install boto3 openpyxl
  - AWS CLI installed and configured (https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)
  - A named AWS CLI profile with credentials that have the permissions listed below
  - An AWS Config multi-account / multi-region aggregator already deployed

REQUIRED IAM PERMISSIONS
-------------------------
The profile used must be able to call:
  - config:SelectAggregateResourceConfig   (on the aggregator)
  - rds:DescribeDBMajorEngineVersions      (in the region you specify)
  - sts:GetCallerIdentity                  (used to validate the session)

USAGE
-----
  python RDS_ExtendedSupport_Query_standalone.py

You will be prompted for:
  1. AWS profile name   — the named profile in ~/.aws/config (default: "default")
  2. AWS region         — the region where your Config aggregator lives (default: us-east-1)
  3. Config aggregator name — the exact name of your multi-account aggregator

OUTPUT
------
Files are written to:  ~/rds_extended_support_exports/
  - rds_extended_support_<YYYYMMDD_HHMMSS>.xlsx   (the report)
  - rds_extended_support_<YYYYMMDD_HHMMSS>.log    (execution log)
"""

import boto3
import configparser
import json
import logging
import os
import shlex
import subprocess
import sys
from datetime import datetime
from botocore.exceptions import ClientError
import botocore

import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

logger = logging.getLogger(__name__)

# Output directory — resolves to the current user's home folder on any OS.
# All .xlsx reports and .log files are written here.
OUTPUT_DIR = os.path.join(os.path.expanduser('~'), 'rds_extended_support_exports')

# ---------------------------------------------------------------------------
# Excel cell styles
# ---------------------------------------------------------------------------
# Dark-blue header row
HEADER_FILL  = PatternFill(start_color='1F4E79', end_color='1F4E79', fill_type='solid')
HEADER_FONT  = Font(color='FFFFFF', bold=True)
# Amber — version not found in the lifecycle catalogue (needs investigation)
WARN_FILL    = PatternFill(start_color='FFEB9C', end_color='FFEB9C', fill_type='solid')
WARN_FONT    = Font(color='9C5700', bold=True)
# Red — resource is actively in Extended Support (additional AWS charges apply)
EXPIRED_FILL = PatternFill(start_color='FFC7CE', end_color='FFC7CE', fill_type='solid')
EXPIRED_FONT = Font(color='9C0006', bold=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def create_logger(logger_name: str, log_path: str, log_file_name: str):
    """
    Configures a logger that writes to both a file and the console.

    Args:
        logger_name:   The Python logger namespace (typically __name__).
        log_path:      Directory where the log file will be created.
                       Created automatically if it does not exist.
        log_file_name: Filename for the log file (no path component).

    Returns:
        The configured logging.Logger instance.
    """
    os.makedirs(log_path, exist_ok=True)
    _logger = logging.getLogger(logger_name)
    _logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s ::%(levelname)s:: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    # Write structured log lines to a file for later review
    file_handler = logging.FileHandler(os.path.join(log_path, log_file_name))
    file_handler.setFormatter(formatter)
    # Mirror output to the terminal so the user can follow progress in real time
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    _logger.addHandler(file_handler)
    _logger.addHandler(console_handler)
    return _logger


def validate_sso_token(session) -> bool:
    """
    Verifies that the boto3 session has valid credentials by calling
    sts:GetCallerIdentity.

    If the token has expired (common with AWS SSO / IAM Identity Center
    profiles), the function automatically triggers 'aws sso login' for the
    correct profile and returns True once the browser flow completes.

    For profiles that use source_profile chaining, the function reads
    ~/.aws/config to find the base SSO profile to log in with.

    Args:
        session: An active boto3.Session object.

    Returns:
        True  — credentials are valid (or were successfully refreshed).
        False — login attempt failed; the script should not continue.
    """
    def _get_sso_profile(profile_name):
        """
        Resolves the SSO login profile, following source_profile chains.
        Some role-assumption profiles delegate their SSO session to a
        separate base profile; we need to log in with that base profile.
        """
        config_path = os.path.expanduser('~/.aws/config')
        config = configparser.ConfigParser()
        config.read(config_path)
        # ~/.aws/config uses "profile <name>" as the section header for all
        # profiles except the literal "default" profile.
        section_name = f'profile {profile_name}' if profile_name != 'default' else 'default'
        if section_name in config and 'source_profile' in config[section_name]:
            return config[section_name]['source_profile']
        return profile_name

    try:
        # A successful GetCallerIdentity call confirms the credentials work.
        session.client('sts').get_caller_identity()
        return True
    except (botocore.exceptions.TokenRetrievalError,
            botocore.exceptions.UnauthorizedSSOTokenError) as e:
        # Token is expired — attempt an interactive SSO login.
        logger.info(e)
        login_profile = _get_sso_profile(session.profile_name)
        logger.info(f"SSO token for profile '{login_profile}' is expired. Initiating login...")
        try:
            subprocess.run(shlex.split(f"aws sso login --profile {login_profile}"))
            return True
        except subprocess.CalledProcessError as sso_error:
            logger.info(f"Failed to login with SSO: {sso_error}")
            return False
    except Exception as e:
        logger.info(e)
        return False


# ---------------------------------------------------------------------------
# Engine version catalogue
# ---------------------------------------------------------------------------

# Only these open-source engines participate in the RDS Extended Support
# programme and incur additional charges after standard support ends.
# Commercial engines (Oracle, SQL Server) have their own support contracts.
ES_ELIGIBLE_ENGINES = {'mysql', 'postgres', 'aurora-mysql', 'aurora-postgresql'}


def build_engine_version_map(rds_client) -> dict:
    """
    Builds a catalogue of RDS engine major versions and their lifecycle dates
    by calling describe_db_major_engine_versions for every relevant engine.

    The catalogue is keyed by (engine, major_version) tuples, e.g.:
        ('mysql', '8.0')  ->  {'standard_support_end': datetime, 'extended_support_end': datetime}

    Lifecycle dates are sourced from the SupportedEngineLifecycles list
    returned by the API:
      - 'open-source-rds-standard-support'  -> standard support end date
      - 'open-source-rds-extended-support'  -> extended support end date

    Commercial engines (Oracle, SQL Server, MariaDB) are queried too so that
    their versions appear in the catalogue and can be labelled "Not ES Eligible"
    rather than "Unknown".

    Args:
        rds_client: A boto3 RDS client.

    Returns:
        dict keyed by (engine_str, major_version_str).
    """
    from datetime import timezone
    version_map = {}
    # Query ES-eligible engines plus commercial ones so every engine type
    # gets a catalogue entry and can be correctly classified.
    engines_to_query = list(ES_ELIGIBLE_ENGINES) + [
        'mariadb', 'oracle-ee', 'sqlserver-se', 'sqlserver-ee', 'sqlserver-ex', 'sqlserver-web'
    ]
    for engine in engines_to_query:
        try:
            paginator = rds_client.get_paginator('describe_db_major_engine_versions')
            for page in paginator.paginate(Engine=engine):
                for ver in page['DBMajorEngineVersions']:
                    std_end = None
                    es_end  = None
                    # Extract the two lifecycle end dates from the nested list
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
            # Some engines may not be available in every region — log and continue.
            logger.debug(f"describe_db_major_engine_versions({engine}): {e.response['Error']['Code']}")
    logger.info(f"Engine version catalogue built: {len(version_map)} entries")
    return version_map


def _major_version(engine: str, engine_version: str, version_map: dict) -> str:
    """
    Resolves a full engine version string (e.g. '8.0.32') to the major version
    key that exists in version_map (e.g. '8.0').

    The Config aggregator stores the full patch version, but the lifecycle
    catalogue is keyed by major version only.  This function tries progressively
    shorter dot-separated prefixes until it finds a match.

    Example resolution path for '8.0.32' with engine 'mysql':
        tries ('mysql', '8.0.32') -> not found
        tries ('mysql', '8.0')    -> found -> returns '8.0'

    Args:
        engine:         Lowercase engine name, e.g. 'mysql'.
        engine_version: Full version string from Config, e.g. '8.0.32'.
        version_map:    The catalogue built by build_engine_version_map.

    Returns:
        The matched major version string, or a best-guess two-part prefix if
        no match is found (triggers an 'Unknown' label downstream).
    """
    parts = engine_version.split('.')
    # Build candidates from longest to shortest: ['8.0.32', '8.0', '8']
    candidates = ['.'.join(parts[:i]) for i in range(len(parts), 0, -1)]
    for candidate in candidates:
        if (engine, candidate) in version_map:
            return candidate
    # No match — return a two-part prefix as a best guess for the log message
    return '.'.join(parts[:2]) if len(parts) >= 2 else parts[0]


def get_es_label(engine: str, engine_version: str, version_map: dict) -> tuple:
    """
    Determines the Extended Support status label for a single RDS resource.

    Classification logic:
      1. Empty engine string              -> 'Unknown'
      2. Engine not in ES_ELIGIBLE_ENGINES -> 'Not ES Eligible'
      3. Version not in catalogue          -> 'Unknown (vX.Y not in catalogue)'
      4. today > standard_support_end      -> 'In Extended Support'
      5. Otherwise                         -> 'Standard Support'

    Args:
        engine:         Engine name as returned by Config (may be mixed case).
        engine_version: Full version string, e.g. '14.10'.
        version_map:    Catalogue from build_engine_version_map.

    Returns:
        Tuple of (status_label, standard_support_end_str, extended_support_end_str).
        Date strings are formatted YYYY-MM-DD, or '' if not available.
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
        # Version exists in the environment but not in the API response —
        # log details at DEBUG level to help with troubleshooting.
        logger.debug(f"No catalogue match: engine='{engine_lower}' version='{engine_version}' derived_major='{major}'")
        logger.debug(f"Available keys for engine: {[k for k in version_map if k[0] == engine_lower]}")
        return (f'Unknown (v{major} not in catalogue)', '', '')

    std_end = info['standard_support_end']
    es_end  = info['extended_support_end']

    std_end_str = std_end.strftime('%Y-%m-%d') if std_end else ''
    es_end_str  = es_end.strftime('%Y-%m-%d')  if es_end  else ''

    # Compare UTC now against the standard support end date to determine status
    if std_end and datetime.now(tz=timezone.utc) > std_end:
        return ('In Extended Support', std_end_str, es_end_str)
    return ('Standard Support', std_end_str, es_end_str)


# ---------------------------------------------------------------------------
# Config aggregator query
# ---------------------------------------------------------------------------

def query_config_aggregator(config_client, aggregator_name: str, resource_type: str) -> list:
    """
    Runs a SQL-like query against the Config aggregator and returns all
    matching resource records as a list of dicts.

    The query selects the fields needed to build the report rows.  Pagination
    is handled automatically so all accounts/regions are covered regardless
    of how many resources exist.

    Args:
        config_client:    A boto3 Config client pointed at the aggregator's home region.
        aggregator_name:  The exact name of the Config aggregator.
        resource_type:    AWS resource type string, e.g. 'AWS::RDS::DBInstance'.

    Returns:
        List of dicts, one per resource record.  Each dict contains keys:
        accountId, awsRegion, resourceId, resourceName, arn, configuration, tags.
    """
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
            ConfigurationAggregatorName=aggregator_name,
            Expression=query
        ):
            # Each item in Results is a JSON string — parse it to a dict
            for item in page['Results']:
                results.append(json.loads(item))
    except ClientError as e:
        logger.error(f"Config query failed for {resource_type}: {e.response['Error']}")
    return results


# ---------------------------------------------------------------------------
# Row builder helpers
# ---------------------------------------------------------------------------

def _parse_cfg(item: dict) -> dict:
    """
    Extracts and normalises the 'configuration' field from a Config record.

    The Config aggregator may return the configuration block as either a
    nested dict or a JSON string depending on the resource type and API version.
    This function always returns a plain dict.
    """
    cfg = item.get('configuration', {})
    if isinstance(cfg, str):
        try:
            return json.loads(cfg)
        except Exception:
            return {}
    return cfg or {}


def _str_val(field) -> str:
    """
    Safely coerces a Config field value to a plain string.

    Some Config fields (e.g. endpoint addresses) are returned as plain strings
    in some API versions and as {'value': '...'} or {'address': '...'} dicts
    in others.  This helper normalises both forms.
    """
    if isinstance(field, dict):
        return str(field.get('value', '') or field.get('address', ''))
    return str(field) if field is not None else ''


def _owner_tag(item: dict) -> str:
    """
    Extracts the value of the 'Owner' tag from a Config resource record.

    Config returns tags in two possible shapes depending on the resource type:
      - A list of {'key': ..., 'value': ...} dicts  (most resource types)
      - A plain {'Owner': ..., 'owner': ...} dict   (some older resource types)

    The key comparison is case-insensitive to handle tagging inconsistencies.
    Returns an empty string if no Owner tag is present.
    """
    tags = item.get('tags', [])
    if isinstance(tags, list):
        return next((t['value'] for t in tags if t.get('key', '').lower() == 'owner'), '')
    if isinstance(tags, dict):
        return tags.get('Owner', tags.get('owner', ''))
    return ''


# ---------------------------------------------------------------------------
# Row builders
# ---------------------------------------------------------------------------

def build_instance_rows(config_items: list, version_map: dict) -> list:
    """
    Converts a list of AWS::RDS::DBInstance Config records into flat report rows.

    Each row is a dict whose keys match INSTANCE_HEADERS so it can be written
    directly to the Excel sheet.  The ES status and lifecycle dates are looked
    up from version_map via get_es_label.

    Args:
        config_items: Raw records from query_config_aggregator.
        version_map:  Catalogue from build_engine_version_map.

    Returns:
        List of row dicts.
    """
    rows = []
    for item in config_items:
        cfg            = _parse_cfg(item)
        engine         = cfg.get('engine', '')
        engine_version = cfg.get('engineVersion', '')
        db_id          = cfg.get('dBInstanceIdentifier', '') or item.get('resourceName', '')
        # endpoint may be a dict with 'address'/'port' keys, or a plain string
        endpoint       = cfg.get('endpoint') or {}
        dns_name       = endpoint.get('address', '') if isinstance(endpoint, dict) else _str_val(endpoint)
        port           = str(endpoint.get('port', '')) if isinstance(endpoint, dict) else ''

        es_status, std_end, es_end = get_es_label(engine, engine_version, version_map)

        rows.append({
            'Resource Type':        'DB Instance',
            'Account ID':           item.get('accountId', ''),
            'Region':               item.get('awsRegion', ''),
            'DB Identifier':        db_id,
            'ARN':                  item.get('arn', ''),
            'DNS Name':             dns_name,
            'Port':                 port,
            'Engine':               engine,
            'Engine Version':       engine_version,
            'DB Instance Class':    cfg.get('dBInstanceClass', ''),
            'Multi-AZ':             cfg.get('multiAZ', ''),
            'Status':               cfg.get('dBInstanceStatus', ''),
            'Cluster Identifier':   cfg.get('dBClusterIdentifier', ''),
            'ES Status':            es_status,
            'Standard Support End': std_end,
            'Extended Support End': es_end,
            'Owner Tag':            _owner_tag(item),
        })
    return rows


def build_cluster_rows(config_items: list, version_map: dict) -> list:
    """
    Converts a list of AWS::RDS::DBCluster Config records into flat report rows.

    Aurora clusters expose a reader endpoint in addition to the primary writer
    endpoint, so this row shape includes a 'Reader Endpoint' column that the
    instance sheet does not have.

    Args:
        config_items: Raw records from query_config_aggregator.
        version_map:  Catalogue from build_engine_version_map.

    Returns:
        List of row dicts.
    """
    rows = []
    for item in config_items:
        cfg            = _parse_cfg(item)
        engine         = cfg.get('engine', '')
        engine_version = cfg.get('engineVersion', '')
        cluster_id     = cfg.get('dBClusterIdentifier', '') or item.get('resourceName', '')

        es_status, std_end, es_end = get_es_label(engine, engine_version, version_map)

        rows.append({
            'Resource Type':        'DB Cluster',
            'Account ID':           item.get('accountId', ''),
            'Region':               item.get('awsRegion', ''),
            'DB Identifier':        cluster_id,
            'ARN':                  item.get('arn', ''),
            'DNS Name':             _str_val(cfg.get('endpoint', '')),
            'Reader Endpoint':      _str_val(cfg.get('readerEndpoint', '')),
            'Engine':               engine,
            'Engine Version':       engine_version,
            'DB Instance Class':    cfg.get('dBClusterInstanceClass', ''),
            'Multi-AZ':             cfg.get('multiAZ', ''),
            'Status':               cfg.get('status', ''),
            'Cluster Identifier':   cluster_id,
            'ES Status':            es_status,
            'Standard Support End': std_end,
            'Extended Support End': es_end,
            'Owner Tag':            _owner_tag(item),
        })
    return rows


# ---------------------------------------------------------------------------
# Excel export
# ---------------------------------------------------------------------------

# Column order for the RDS Instances sheet
INSTANCE_HEADERS = [
    'Resource Type', 'Account ID', 'Region', 'DB Identifier', 'ARN',
    'DNS Name', 'Port', 'Engine', 'Engine Version', 'DB Instance Class',
    'Multi-AZ', 'Status', 'Cluster Identifier',
    'ES Status', 'Standard Support End', 'Extended Support End', 'Owner Tag',
]

# Column order for the Aurora Clusters sheet
# Differs from INSTANCE_HEADERS by the addition of 'Reader Endpoint'
CLUSTER_HEADERS = [
    'Resource Type', 'Account ID', 'Region', 'DB Identifier', 'ARN',
    'DNS Name', 'Reader Endpoint', 'Engine', 'Engine Version', 'DB Instance Class',
    'Multi-AZ', 'Status', 'Cluster Identifier',
    'ES Status', 'Standard Support End', 'Extended Support End', 'Owner Tag',
]


def _write_sheet(wb, title: str, headers: list, rows: list):
    """
    Adds a formatted worksheet to an openpyxl Workbook.

    Formatting applied:
      - Header row: dark-blue background, white bold text, centred
      - 'In Extended Support' cells: red fill (EXPIRED_FILL)
      - 'Unknown ...' cells: amber fill (WARN_FILL)
      - Column widths: auto-sized to content, capped at 80 characters

    Args:
        wb:      The openpyxl Workbook to add the sheet to.
        title:   The worksheet tab name.
        headers: Ordered list of column header strings.
        rows:    List of row dicts (keys must match headers).
    """
    ws = wb.create_sheet(title=title)
    ws.append(headers)

    # Style the header row
    for cell in ws[1]:
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = Alignment(horizontal='center')

    # Locate the ES Status column index (1-based) for conditional formatting
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

    # Auto-size columns based on the widest value in each column
    for col_cells in ws.columns:
        width = max(len(str(c.value or '')) for c in col_cells) + 4
        ws.column_dimensions[get_column_letter(col_cells[0].column)].width = min(width, 80)


def export_to_excel(instance_rows: list, cluster_rows: list, output_path: str):
    """
    Creates a new Excel workbook with two sheets and saves it to disk.

    Args:
        instance_rows: Rows from build_instance_rows.
        cluster_rows:  Rows from build_cluster_rows.
        output_path:   Full path for the output .xlsx file.
    """
    wb = openpyxl.Workbook()
    wb.remove(wb.active)  # Remove the default empty sheet created by openpyxl
    _write_sheet(wb, 'RDS Instances',  INSTANCE_HEADERS, instance_rows)
    _write_sheet(wb, 'Aurora Clusters', CLUSTER_HEADERS, cluster_rows)
    wb.save(output_path)
    logger.info(f"Results saved to: {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    """
    Entry point.  Prompts for runtime configuration, orchestrates the data
    collection, and writes the output files.

    Execution steps:
      1. Create the output directory and start logging
      2. Prompt for AWS profile, region, and aggregator name
      3. Validate / refresh the SSO session
      4. Build the engine version catalogue (single RDS API call)
      5. Query the Config aggregator for DB Instances and DB Clusters
      6. Build report rows and export to Excel
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    # Log file name is generated from a fixed timestamp — no user input in the path
    create_logger(__name__, OUTPUT_DIR, f'rds_extended_support_{timestamp}.log')

    # --- Runtime configuration prompts ---
    profile = input("AWS profile name [default]: ").strip() or 'default'
    region  = input("AWS region [us-west-2]: ").strip() or 'us-west-2'

    aggregator_name = input("Config aggregator name: ").strip()
    if not aggregator_name:
        logger.error("Config aggregator name is required.")
        sys.exit(1)

    # --- Session setup and credential validation ---
    session = boto3.Session(profile_name=profile, region_name=region)
    validate_sso_token(session)

    rds_client    = session.client('rds',    region_name=region)
    config_client = session.client('config', region_name=region)

    # --- Build engine lifecycle catalogue ---
    logger.info("Building engine version catalogue from describe_db_major_engine_versions...")
    version_map = build_engine_version_map(rds_client)

    # --- Query Config aggregator ---
    logger.info("Querying Config aggregator for DB Instances...")
    instance_items = query_config_aggregator(config_client, aggregator_name, 'AWS::RDS::DBInstance')
    logger.info(f"Found {len(instance_items)} DB Instance records")

    logger.info("Querying Config aggregator for DB Clusters...")
    cluster_items = query_config_aggregator(config_client, aggregator_name, 'AWS::RDS::DBCluster')
    logger.info(f"Found {len(cluster_items)} DB Cluster records")

    # --- Build rows and export ---
    instance_rows = build_instance_rows(instance_items, version_map)
    cluster_rows  = build_cluster_rows(cluster_items,  version_map)

    output_file = os.path.join(OUTPUT_DIR, f'rds_extended_support_{timestamp}.xlsx')
    export_to_excel(instance_rows, cluster_rows, output_file)
    logger.info(f"Done. {len(instance_rows)} instances, {len(cluster_rows)} clusters exported.")


if __name__ == '__main__':
    main()
