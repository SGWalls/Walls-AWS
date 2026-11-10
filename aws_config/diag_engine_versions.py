"""
diag_engine_versions.py  —  dump describe_db_major_engine_versions raw output
Run this to see exactly what fields/values the API returns so we can fix the ES logic.
"""
import boto3
import json

profile = input("AWS SSO profile name [ct_master]: ").strip() or 'ct_master'
session = boto3.Session(profile_name=profile, region_name='us-west-2')
rds     = session.client('rds', region_name='us-west-2')

for engine in ('mysql', 'postgres', 'aurora-mysql', 'aurora-postgresql'):
    print(f"\n{'='*60}")
    print(f"ENGINE: {engine}")
    print('='*60)
    try:
        paginator = rds.get_paginator('describe_db_major_engine_versions')
        for page in paginator.paginate(Engine=engine):
            for ver in page['DBMajorEngineVersions']:
                print(json.dumps(ver, indent=2, default=str))
    except Exception as e:
        print(f"  ERROR: {e}")
