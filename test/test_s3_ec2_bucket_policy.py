#!/usr/bin/env python3
"""
S3 EC2 Bucket Policy Test Cases
Descriptive test scenarios for Excel documentation

Bucket Policy Summary:
- Allows access only from EC2 instances within organization o-w3wk3dircz
- Requires ec2:SourceInstanceArn context (only available from EC2)
- Denies all other access patterns
"""

# Test Case Definitions for Excel Documentation

TEST_CASES = [
    {
        "Test Name": "EC2-SameAccount-InstanceProfile",
        "Test Description": "Using credentials from the EC2 Instance profile on an EC2 instance in the same AWS Account that owns the bucket.",
        "Expected Result": "SUCCESS - Full read/write access granted. Policy allows access from EC2 instances within the organization.",
        "Test Steps": "1. Launch EC2 instance in bucket owner account\n2. Attach IAM role with S3 permissions\n3. Attempt S3 operations from instance\n4. Verify successful access",
        "Prerequisites": "EC2 instance in same account as bucket, IAM role attached to instance"
    },
    {
        "Test Name": "EC2-SameAccount-FederatedRole-SameAccount",
        "Test Description": "Using credentials from an AWS Identity Center federated Role for the same AWS account that hosts the bucket on an EC2 Instance in the same AWS Account that owns the bucket.",
        "Expected Result": "SUCCESS - Full read/write access granted. Federated role provides valid credentials with ec2:SourceInstanceArn context.",
        "Test Steps": "1. Configure Identity Center federated role for bucket owner account\n2. Launch EC2 instance and assume federated role\n3. Attempt S3 operations\n4. Verify successful access",
        "Prerequisites": "Identity Center configured, federated role with S3 permissions, EC2 instance"
    },
    {
        "Test Name": "EC2-SameAccount-FederatedRole-CrossAccount",
        "Test Description": "Using credentials from an AWS Identity Center federated Role for a separate AWS account than the AWS Account that hosts the bucket on an EC2 Instance in the same AWS Account that owns the bucket.",
        "Expected Result": "DENIED - Access denied due to cross-account federated role. Policy restricts to same organization but federated roles may not have proper trust relationship.",
        "Test Steps": "1. Configure federated role in different account\n2. Launch EC2 in bucket owner account\n3. Assume cross-account federated role\n4. Attempt S3 operations\n5. Verify access denied",
        "Prerequisites": "Cross-account federated role, EC2 instance in bucket owner account"
    },
    {
        "Test Name": "EC2-CrossAccount-SameOrg",
        "Test Description": "EC2 instance in different AWS account within same organization (o-w3wk3dircz) attempting bucket access.",
        "Expected Result": "SUCCESS - Access granted. Policy allows any role within the organization when accessed from EC2.",
        "Test Steps": "1. Launch EC2 in different account within org\n2. Attach IAM role with S3 permissions\n3. Attempt S3 operations\n4. Verify successful access",
        "Prerequisites": "EC2 instance in different account within same org, IAM role"
    },
    {
        "Test Name": "EC2-CrossAccount-DifferentOrg",
        "Test Description": "EC2 instance in AWS account outside organization (different PrincipalOrgId) attempting bucket access.",
        "Expected Result": "DENIED - Access denied due to PrincipalOrgId mismatch. Policy restricts access to organization o-w3wk3dircz only.",
        "Test Steps": "1. Launch EC2 in account outside org\n2. Attach IAM role with S3 permissions\n3. Attempt S3 operations\n4. Verify access denied with AccessDenied error",
        "Prerequisites": "EC2 instance in account outside target organization"
    },
    {
        "Test Name": "Lambda-SameAccount",
        "Test Description": "Lambda function in same account as bucket attempting S3 access using IAM role.",
        "Expected Result": "DENIED - Access denied because Lambda execution does not provide ec2:SourceInstanceArn context.",
        "Test Steps": "1. Create Lambda function in bucket owner account\n2. Attach IAM role with S3 permissions\n3. Execute Lambda to attempt S3 operations\n4. Verify access denied",
        "Prerequisites": "Lambda function, IAM execution role with S3 permissions"
    },
    {
        "Test Name": "ECS-SameAccount",
        "Test Description": "ECS task in same account as bucket attempting S3 access using task role.",
        "Expected Result": "DENIED - Access denied because ECS task execution does not provide ec2:SourceInstanceArn context.",
        "Test Steps": "1. Create ECS task in bucket owner account\n2. Configure task role with S3 permissions\n3. Run task to attempt S3 operations\n4. Verify access denied",
        "Prerequisites": "ECS cluster, task definition with IAM task role"
    },
    {
        "Test Name": "LocalCLI-IAMUser",
        "Test Description": "Local AWS CLI using IAM user credentials attempting bucket access.",
        "Expected Result": "DENIED - Access denied because local execution does not provide ec2:SourceInstanceArn context.",
        "Test Steps": "1. Configure AWS CLI with IAM user credentials\n2. Attempt S3 operations via CLI\n3. Verify access denied with AccessDenied error",
        "Prerequisites": "AWS CLI configured with IAM user credentials having S3 permissions"
    },
    {
        "Test Name": "LocalCLI-AssumedRole",
        "Test Description": "Local AWS CLI using assumed IAM role credentials attempting bucket access.",
        "Expected Result": "DENIED - Access denied because local execution does not provide ec2:SourceInstanceArn context, regardless of role type.",
        "Test Steps": "1. Configure AWS CLI to assume IAM role\n2. Attempt S3 operations via CLI\n3. Verify access denied",
        "Prerequisites": "AWS CLI configured to assume role, IAM role with S3 permissions"
    },
    {
        "Test Name": "CloudShell-SameAccount",
        "Test Description": "AWS CloudShell in same account attempting bucket access.",
        "Expected Result": "DENIED - Access denied because CloudShell does not provide ec2:SourceInstanceArn context.",
        "Test Steps": "1. Open CloudShell in bucket owner account\n2. Attempt S3 operations\n3. Verify access denied",
        "Prerequisites": "CloudShell access in bucket owner account"
    },
    {
        "Test Name": "EC2-NoRole",
        "Test Description": "EC2 instance without IAM role attempting bucket access.",
        "Expected Result": "DENIED - Access denied due to lack of AWS credentials, not policy restriction.",
        "Test Steps": "1. Launch EC2 instance without IAM role\n2. Attempt S3 operations\n3. Verify credential error",
        "Prerequisites": "EC2 instance without attached IAM role"
    },
    {
        "Test Name": "EC2-InsufficientPermissions",
        "Test Description": "EC2 instance with IAM role lacking S3 permissions attempting bucket access.",
        "Expected Result": "DENIED - Access denied due to insufficient IAM permissions, not bucket policy.",
        "Test Steps": "1. Launch EC2 with role having no S3 permissions\n2. Attempt S3 operations\n3. Verify AccessDenied due to IAM policy",
        "Prerequisites": "EC2 instance with IAM role lacking S3 permissions"
    }
]

# Additional validation scenarios
VALIDATION_TESTS = [
    {
        "Test Name": "Policy-Structure-Validation",
        "Test Description": "Validate bucket policy contains correct conditions and principals.",
        "Expected Result": "Policy contains: PrincipalOrgId=o-w3wk3dircz, ec2:SourceInstanceArn null condition=false, Principal=arn:aws:iam::*:role/*",
        "Test Steps": "1. Retrieve bucket policy via S3 API\n2. Parse JSON structure\n3. Verify all required conditions present\n4. Confirm policy syntax",
        "Prerequisites": "S3 GetBucketPolicy permissions"
    },
    {
        "Test Name": "Policy-Effect-Verification",
        "Test Description": "Confirm policy effect is 'Allow' and no conflicting 'Deny' statements exist.",
        "Expected Result": "Single Allow statement with no Deny statements that could override access.",
        "Test Steps": "1. Review complete bucket policy\n2. Verify Effect=Allow\n3. Check for conflicting Deny statements\n4. Validate statement priority",
        "Prerequisites": "Access to view complete bucket policy"
    }
]

def print_test_cases():
    """Print all test cases in a format suitable for Excel import"""
    print("S3 EC2 Bucket Policy Test Cases")
    print("=" * 50)
    
    all_tests = TEST_CASES + VALIDATION_TESTS
    
    for i, test in enumerate(all_tests, 1):
        print(f"\nTest {i}: {test['Test Name']}")
        print(f"Description: {test['Test Description']}")
        print(f"Expected Result: {test['Expected Result']}")
        if 'Test Steps' in test:
            print(f"Test Steps: {test['Test Steps']}")
        if 'Prerequisites' in test:
            print(f"Prerequisites: {test['Prerequisites']}")
        print("-" * 40)

if __name__ == "__main__":
    print_test_cases()