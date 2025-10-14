#!/usr/bin/env python3
"""
Simple validation script for S3 bucket policy testing.
Run this from different AWS contexts to validate policy behavior.
"""

import boto3
import json
from botocore.exceptions import ClientError

def test_s3_access(bucket_name, test_key="policy-test/test.log"):
    """Test S3 access and report results"""
    
    s3 = boto3.client('s3')
    sts = boto3.client('sts')
    
    print("=== S3 Bucket Policy Validation ===\n")
    
    # Show current identity
    try:
        identity = sts.get_caller_identity()
        print(f"Testing as: {identity['Arn']}")
        print(f"Account: {identity['Account']}")
        print(f"User ID: {identity['UserId']}\n")
    except Exception as e:
        print(f"Failed to get identity: {e}\n")
    
    # Test PUT operation
    print("Testing PUT operation...")
    try:
        s3.put_object(
            Bucket=bucket_name,
            Key=test_key,
            Body=b"Test content from validation script"
        )
        print("✓ PUT: SUCCESS - Able to write to bucket")
        put_success = True
    except ClientError as e:
        print(f"✗ PUT: DENIED - {e.response['Error']['Code']}: {e.response['Error']['Message']}")
        put_success = False
    
    # Test GET operation (only if PUT succeeded)
    if put_success:
        print("Testing GET operation...")
        try:
            response = s3.get_object(Bucket=bucket_name, Key=test_key)
            print("✓ GET: SUCCESS - Able to read from bucket")
        except ClientError as e:
            print(f"✗ GET: DENIED - {e.response['Error']['Code']}: {e.response['Error']['Message']}")
    
    # Test policy retrieval
    print("Testing policy retrieval...")
    try:
        response = s3.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(response['Policy'])
        print("✓ Policy retrieved successfully")
        
        # Validate key conditions
        statement = policy['Statement'][0]
        org_id = statement['Condition']['StringEquals']['aws:PrincipalOrgId']
        ec2_condition = statement['Condition']['Null']['ec2:SourceInstanceArn']
        
        print(f"  - Required Org ID: {org_id}")
        print(f"  - EC2 Source Required: {ec2_condition == 'false'}")
        
    except ClientError as e:
        print(f"✗ Policy retrieval failed: {e.response['Error']['Code']}")

def main():
    bucket_name = input("Enter S3 bucket name to test: ").strip()
    if not bucket_name:
        bucket_name = "myS3Bucket"  # Default from policy
    
    test_s3_access(bucket_name)
    
    print("\n=== Test Scenarios ===")
    print("Run this script from:")
    print("1. EC2 instance with IAM role (should succeed)")
    print("2. Local machine with IAM user (should fail)")
    print("3. Lambda function (should fail)")
    print("4. ECS task (should fail)")
    print("5. Different AWS organization (should fail)")

if __name__ == "__main__":
    main()