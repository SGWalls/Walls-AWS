import boto3

def check_cluster_instances(cluster_identifier):
    rds = session.client('rds')
    
    response = rds.describe_db_clusters(
        DBClusterIdentifier=cluster_identifier
    )
    members = response['DBClusters'][0]['DBClusterMembers']
    reader_count = sum(1 for member in members if not member['IsClusterWriter'])
    
    if len(members) == 1 and reader_count == 0:
        print('Cluster has only primary instance')
        return True
    else:
        print(f'Cluster has {reader_count} read replicas')
        return False

session = boto3.Session(profile_name='cdm_dev',region_name="us-west-2")

check_cluster_instances('arn:aws:rds:us-west-2:838001389413:cluster:cdm-prd-aurora-ms-resonant')