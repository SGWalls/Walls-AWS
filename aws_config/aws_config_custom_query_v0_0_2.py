import boto3
import json
import csv
from datetime import datetime
from botocore.exceptions import ClientError

class ConfigAggregatorExporter:
    def __init__(self, aggregator_name):
        self.config_client = boto3.Session(profile_name='gloca_audit',region_name='us-west-2').client('config')
        self.aggregator_name = aggregator_name

    def execute_query(self, query):
        """
        Execute AWS Config query with pagination
        """
        try:
            paginator = self.config_client.get_paginator('select_aggregate_resource_config')
            all_results = []
            
            for page in paginator.paginate(
                ConfigurationAggregatorName=self.aggregator_name,
                Expression=query
            ):
                for result in page['Results']:
                    all_results.append(json.loads(result))
            return all_results
        except ClientError as e:
            print(f"AWS Error: {e.response['Error']}")
            raise

    def get_all_resources(self):
        """
        Get all resources from the aggregator
        """
        query = """
            SELECT
                resourceId,
                resourceType,
                accountId,
                awsRegion,
                configuration,
                tags
            WHERE
                resourceType != 'AWS::Config::ResourceCompliance'
        """
        return self.execute_query(query)

    def write_to_csv(self, resources, filename=None):
        """
        Write resources to CSV file
        """
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'aws_resources_{timestamp}.csv'

        # Define CSV headers
        headers = [
            'Resource ID',
            'Resource Type',
            'Account ID',
            'Region',
            'Resource Name',
            'Tags'
        ]

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)

                for resource in resources:
                    # Extract resource name from configuration if available
                    resource_name = 'N/A'
                    if 'configuration' in resource:
                        config = resource['configuration']
                        if isinstance(config, dict):
                            # Try common name fields
                            name_fields = ['name', 'Name', 'bucketName', 'functionName', 
                                         'databaseName', 'instanceId', 'groupName']
                            for field in name_fields:
                                if field in config:
                                    resource_name = config[field]
                                    break

                    # Format tags
                    tags = []
                    if 'tags' in resource:
                        if isinstance(resource['tags'], list):
                            tags = [f"{tag.get('Key', '')}:{tag.get('Value', '')}" 
                                   for tag in resource['tags']]
                        elif isinstance(resource['tags'], dict):
                            tags = [f"{k}:{v}" for k, v in resource['tags'].items()]
                    tags_str = '; '.join(tags)

                    # Write row
                    writer.writerow([
                        resource.get('resourceId', 'N/A'),
                        resource.get('resourceType', 'N/A'),
                        resource.get('accountId', 'N/A'),
                        resource.get('awsRegion', 'N/A'),
                        resource_name,
                        tags_str
                    ])

            print(f"CSV file created successfully: {filename}")
            return filename

        except Exception as e:
            print(f"Error writing CSV: {e}")
            raise

def main():
    try:
        # Initialize with Control Tower aggregator
        aggregator_name = 'aws-controltower-GuardrailsComplianceAggregator'
        exporter = ConfigAggregatorExporter(aggregator_name)

        print("Querying AWS Config aggregator...")
        resources = exporter.get_all_resources()

        if not resources:
            print("No resources found")
            return

        print(f"Found {len(resources)} resources")
        
        # Create CSV file
        csv_file = exporter.write_to_csv(resources)
        print(f"Resources exported to: {csv_file}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
