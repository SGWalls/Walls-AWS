# Cross-Account S3 Copy Lambda Function

## Overview
This C# Lambda function runs in AccountA and assumes an IAM role in AccountB to copy S3 objects between accounts.

## Required IAM Permissions

### Lambda Execution Role (AccountA)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
      ],
      "Resource": "arn:aws:iam::ACCOUNT-B:role/CrossAccountS3AccessRole"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl"
      ],
      "Resource": "arn:aws:s3:::account-a-bucket/*"
    }
  ]
}
```

### Cross-Account Role (AccountB)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject"
      ],
      "Resource": "arn:aws:s3:::account-b-bucket/*"
    }
  ]
}
```

### Trust Policy for AccountB Role
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT-A:role/lambda-execution-role"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

## Usage
Deploy the Lambda and invoke with:
```json
{
  "AccountBRoleArn": "arn:aws:iam::ACCOUNT-B:role/CrossAccountS3AccessRole",
  "AccountBBucket": "source-bucket-name",
  "AccountABucket": "destination-bucket-name",
  "ObjectKey": "path/to/file.txt"
}
```