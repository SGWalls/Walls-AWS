# AWS Account Management and Automation Toolkit

This project provides a comprehensive set of Python scripts for managing and automating various AWS account tasks across multiple accounts and services.

The toolkit offers functionality for deploying CloudFormation stacks, managing IAM roles and policies, configuring S3 bucket policies, and interacting with services like AppStream, Cognito, and Route 53.

## Repository Structure

- `AccountMigration/`: Scripts for AWS account migration tasks
- `aws_Account/`: Scripts for managing AWS account settings (e.g., password policies)
- `aws_cloudformation/`: CloudFormation deployment scripts
- `aws_Cognito/`: Scripts for managing Cognito user pools
- `aws_config/`: AWS Config related scripts
- `aws_EC2/`: EC2 instance management scripts
- `aws_IAMTasks/`: IAM role and policy management scripts
- `aws_S3Scripts/`: S3 bucket policy and access management scripts
- `aws_SSO/`: AWS SSO (Single Sign-On) related scripts
- `aws_transitgateway_Tasks/`: Transit Gateway management scripts
- `helpers/`: Utility functions and helper classes
- `lambda_functions/`: AWS Lambda function code
- `test/`: Test scripts for the toolkit

## Usage Instructions

### Installation

1. Ensure you have Python 3.6+ installed
2. Install required dependencies:
   ```
   pip install boto3 pyyaml
   ```
3. Configure AWS CLI with appropriate credentials and profiles

### Getting Started

1. Clone the repository
2. Navigate to the desired script directory
3. Run the script with appropriate arguments, e.g.:
   ```
   python aws_cloudformation/CFTDeploy_v1_0_0.py -s MyStack -d /path/to/template -f template.yaml -t 123456789012
   ```

### Common Use Cases

1. Deploying CloudFormation stacks:
   Use `aws_cloudformation/CFTDeploy_v1_0_0.py` to deploy or update CloudFormation stacks across multiple accounts.

2. Managing IAM roles:
   Use scripts in the `aws_IAMTasks/` directory to create, modify, or audit IAM roles and policies.

3. Configuring S3 bucket policies:
   Use scripts in the `aws_S3Scripts/` directory to manage S3 bucket policies and public access settings.

4. Automating AWS SSO tasks:
   Use scripts in the `aws_SSO/` directory to manage AWS SSO permission sets and assignments.

### Troubleshooting

- If you encounter "Access Denied" errors, ensure your AWS credentials have the necessary permissions.
- For SSO token-related issues, run `aws sso login --profile <profile_name>` to refresh your session.
- Check the log files generated in your Documents folder for detailed error messages and execution logs.

## Data Flow

1. User initiates a script with required parameters
2. Script authenticates with AWS using provided credentials or SSO
3. Script interacts with specified AWS services using boto3 SDK
4. Results are logged and, in some cases, exported to files (e.g., CSV, JSON)

```
[User] -> [Script] -> [AWS Authentication] -> [AWS Services] -> [Logs/Exports]
```

## Deployment

Most scripts in this toolkit are designed to be run locally or in a secure environment with access to AWS credentials. For production use, consider:

1. Implementing proper secret management for AWS credentials
2. Setting up a CI/CD pipeline for automated execution of scripts
3. Implementing additional error handling and monitoring

## Infrastructure

Key AWS resources defined in the scripts include:

- IAM:
  - Roles: "AWSControlTowerExecution", "AppStream_{location}_FleetRole"
  - Policies: Custom policies for AppStream fleets

- CloudFormation:
  - Stacks: Dynamic stack creation and updates

- S3:
  - Buckets: Configuration of bucket policies and public access settings

- Kinesis Firehose:
  - Delivery Streams: For capturing AWS WAF logs

- Lambda:
  - Functions: For processing CloudWatch Logs sent to Kinesis Firehose

Note: Actual resource names and ARNs will depend on your AWS environment and script parameters.