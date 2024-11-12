import boto3
from botocore.exceptions import ClientError

def get_all_resource_counts(region='us-east-1'):
    """
    Get the count of resources for all supported AWS services using AWS Config aggregator.

    :param region: AWS region where the aggregator is located (default is 'us-east-1')
    :return: A dictionary of service names and their resource counts
    """
    try:
        # Create a boto3 session
        session = boto3.Session(profile_name='audit',region_name=region)
        
        # Create a client for AWS Config
        config_client = session.client('config')
        
        # Get the resource counts using the aggregator
        response = config_client.get_aggregate_discovered_resource_counts(
            ConfigurationAggregatorName='aws-controltower-GuardrailsComplianceAggregator',
            # Filters={
            #     'ResourceType': ['AWS::AllSupported']
            # },
            GroupByKey='RESOURCE_TYPE'
        )
        
        resource_counts = {}
        for item in response['GroupedResourceCounts']:
            resource_type = item['GroupName']
            count = item['ResourceCount']
            
            # Extract the service name from the resource type
            service_name = resource_type.split('::')[1].lower()
            
            if service_name not in resource_counts:
                resource_counts[service_name] = {}
            
            resource_counts[service_name][resource_type] = count
        
        return resource_counts

    except ClientError as e:
        print(f"An error occurred: {e}")
        return None

def print_resource_counts(resource_counts):
    """
    Print the resource counts in a formatted manner.

    :param resource_counts: Dictionary of resource counts by service
    """
    if not resource_counts:
        print("No resource counts available.")
        return

    print("Resource Counts by AWS Service (Aggregated):")
    print("============================================")
    
    for service, resources in sorted(resource_counts.items()):
        print(f"\n{service.upper()}:")
        total_count = sum(resources.values())
        print(f"  Total resources: {total_count}")
        for resource_type, count in sorted(resources.items()):
            print(f"  - {resource_type}: {count}")

# Main execution
if __name__ == "__main__":
    region = 'us-west-2'  # Change this to the region where your aggregator is located
    resource_counts = get_all_resource_counts(region)
    
    if resource_counts:
        print_resource_counts(resource_counts)
    else:
        print("Failed to retrieve aggregated resource counts.")
