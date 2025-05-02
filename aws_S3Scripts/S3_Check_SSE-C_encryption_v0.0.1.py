import boto3
from botocore.exceptions import ClientError

def check_ssec_encryption(bucket_name):
    """
    Check if SSE-C encryption is being used in the specified S3 bucket
    
    Args:
        bucket_name (str): Name of the S3 bucket to check
        
    Returns:
        dict: Dictionary containing results of the check
    """
    s3_client = boto3.client('s3')
    ssec_objects = []
    total_objects = 0
    
    try:
        # Create a paginator for handling large buckets
        paginator = s3_client.get_paginator('list_objects_v2')
        
        # Iterate through all objects in the bucket
        for page in paginator.paginate(Bucket=bucket_name):
            if 'Contents' not in page:
                continue
                
            for obj in page['Contents']:
                total_objects += 1
                key = obj['Key']
                
                try:
                    # Attempt to get object metadata
                    s3_client.head_object(
                        Bucket=bucket_name,
                        Key=key
                    )
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    error_message = e.response.get('Error', {}).get('Message', '')
                    
                    # Check if the error indicates SSE-C encryption
                    if error_code == 'InvalidRequest' and 'SSE-C' in error_message:
                        ssec_objects.append(key)
                    elif error_code == '403':
                        # Handle potential permission issues
                        print(f"Warning: Unable to check object {key} due to permissions")
        
        result = {
            'bucket_name': bucket_name,
            'total_objects': total_objects,
            'ssec_encrypted_objects': len(ssec_objects),
            'ssec_object_keys': ssec_objects
        }
        
        return result
        
    except ClientError as e:
        print(f"Error accessing bucket {bucket_name}: {str(e)}")
        raise

# Example usage
if __name__ == "__main__":
    try:
        bucket_name = "XXXXXXXXXXXXXXXX"
        results = check_ssec_encryption(bucket_name)
        
        print(f"\nResults for bucket: {results['bucket_name']}")
        print(f"Total objects: {results['total_objects']}")
        print(f"SSE-C encrypted objects found: {results['ssec_encrypted_objects']}")
        
        if results['ssec_encrypted_objects'] > 0:
            print("\nSSE-C encrypted object keys:")
            for key in results['ssec_object_keys']:
                print(f"- {key}")
                
    except Exception as e:
        print(f"Error: {str(e)}")
