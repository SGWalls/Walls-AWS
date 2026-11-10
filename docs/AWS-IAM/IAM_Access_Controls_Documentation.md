# AWS IAM Access Controls Technical Documentation


## Overview

This document defines the Identity and Access Management (IAM) access controls implemented in Globe Life's AWS environment that are used to ensure security, compliance, and proper governance of AWS resources.


## Scope of Controls

These access controls apply to all access that is created and delegated by the team responsible for centralized AWS Access Management, including:

- **AWS IAM Identity Center Permission Sets**: Permission sets created through AWS IAM Identity Center must implement these controls
- **Centrally Deployed IAM Roles**: Any IAM roles deployed into member accounts by the central IAM Management team must adhere to these controls
- **Delegated Access**: Any access permissions granted to teams or individuals through centrally managed policies must incorporate these restrictions

The controls ensure consistent security posture across all centrally managed access mechanisms while maintaining the principle of least privilege and defense in depth.


## IAM Access Control Requirements

### 1. IAM Role Creation and Modification Controls

**Control**: Creation or modification of any IAM role requires a permissions boundary be defined on the role.

**Implementation Requirements**:
- IAM roles MUST have a permissions boundary configured using an IAM Policy
- The name of the IAM Policy used as the permissions boundary MUST be prefixed with `Boundary_`
- Attempts to create or modify an IAM role without this permissions boundary will receive an 'Access Denied' error

**Notable Exceptions**:
- Permission Sets created in AWS IAM Identity Center for the IT Operations teams responsible for AWS IAM which are approved to create IAM Roles, Users, and Groups without restriction. 

**Policy Example**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SetPermissionBoundary",
      "Effect": "Allow",
      "Action": [
          "iam:AttachRolePolicy",
          "iam:CreateRole",
          "iam:DetachRolePolicy",
          "iam:PutRolePolicy",
          "iam:PutRolePermissionsBoundary",
          "iam:DeleteRolePolicy"
      ],
      "Resource": "*",
      "Condition": {
          "ArnLike": {
              "iam:PermissionsBoundary": "arn:aws:iam::*:policy/Boundary_*"
          }
      }
    }
  ]
}
```

### 2. Boundary Policy Management

**Control**: Only the centralized AWS IAM Management team can manage boundary policies.

**Implementation Requirements**:
- Managed IAM Policies with prefix `Boundary_` can only be created, modified, or deleted by the IAM Management team
- All other users/roles are explicitly denied these actions

**Notable Exceptions**:
- Permission Sets created in AWS IAM Identity Center for the IT Operations teams responsible for AWS IAM which are approved to create IAM Roles, Users, and Groups without restriction. 

**Policy Example**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "iam:CreatePolicy",
        "iam:CreatePolicyVersion",
        "iam:DeletePolicy",
        "iam:DeletePolicyVersion",
        "iam:SetDefaultPolicyVersion"
      ],
      "Resource": "arn:aws:iam::*:policy/Boundary_*"      
    }
  ]
}
```

### 3. Trust Policy Modification Restrictions

**Control**: Trust policies for IAM roles cannot be modified; roles must be recreated for trust policy changes.

**Implementation Requirements**:
- The `iam:UpdateAssumeRolePolicy` action is denied for all users
- If any trust policy modifications are needed, then the Role needs to be re-created.

**Notable Exceptions**:
- Permission Sets created in AWS IAM Identity Center for the IT Operations teams responsible for AWS IAM which are approved to create IAM Roles, Users, and Groups without restriction. 

**Policy Example**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "iam:UpdateAssumeRolePolicy",
      "Resource": "*"
    }
  ]
}
```

### 4. IAM Role Pass Restrictions

**Control**: IAM role passing is limited to specific services with explicit resource targeting.

**Implementation Requirements**:
- `iam:PassRole` action must specify the exact service in conditions
- Resource field must be as specific as possible (individual role ARNs preferred)

**Notable Exceptions**:
- Permission Sets created in AWS IAM Identity Center for the IT Operations teams responsible for AWS IAM which are approved to create IAM Roles, Users, and Groups without restriction. 

**Policy Example**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::ACCOUNT-ID:role/specific-service-role",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "lambda.amazonaws.com"
        }
      }
    }
  ]
}
```

### 5. S3 Access Restrictions

**Control**: S3 access is limited to buckets owned by the local account.

**Implementation Requirements**:
- S3 actions are restricted to buckets within the same AWS account
- Cross-account S3 access is denied unless explicitly granted

**Policy Example**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::*",
        "arn:aws:s3:::*/*"
      ],
      "Condition": {
        "StringEquals": {
          "s3:ResourceAccount": "${aws:PrincipalAccount}"
        }
      }
    }
  ]
}
```

### 6. Lambda VPC Configuration Requirements

**Control**: Lambda functions must be configured with VPC settings for network security controls.

**Implementation Requirements**:
- Lambda function creation/updates require VPC configuration
- Functions without VPC settings are denied
- Access is granted to Lambda via the AWS managed policy "AWSLambda_FullAccess". This control is enforced via a DENY policy in the inline policy

**Policy Example**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "lambda:CreateFunction",
        "lambda:UpdateFunctionConfiguration"
      ],
      "Resource": "*",
      "Condition": {
        "Null": {
          "lambda:VpcIds": "true"
        }
      }
    }
  ]
}
```

### 7. API Gateway Endpoint Type Restrictions

**Control**: API Gateway APIs are limited to private endpoint types only.

**Implementation Requirements**:
- Only private API Gateway endpoints can be created
- Regional and edge-optimized endpoints are denied

**Policy Example**:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "apigateway:POST",
        "apigateway:PUT"
      ],
      "Resource": "arn:aws:apigateway:*::/restapis",
      "Condition": {
        "StringNotEquals": {
          "apigateway:Request/EndpointType": "PRIVATE"
        }
      }
    }
  ]
}
```


## Exception Process

### Exception Criteria
Exceptions to these controls may be granted under the following conditions:
- **Business Justification**: Clear business need that cannot be met within existing controls
- **Security Assessment**: Risk assessment demonstrating acceptable security posture
- **Compensating Controls**: Alternative security measures to mitigate identified risks
- **Time-Limited**: Exceptions should have defined expiration dates where applicable

### Exception Approval Process
1. Submit exception request with detailed justification
2. Security team review and risk assessment
3. IAM Management team approval
4. Implementation with monitoring and review schedule
5. Regular re-evaluation of exception necessity


## Monitoring and Compliance

### CloudTrail Monitoring
Monitor the following API calls for compliance violations:
- `CreateRole` without permissions boundary
- `UpdateAssumeRolePolicy` attempts
- `CreateFunction` without VPC configuration
- `CreateRestApi` with non-private endpoints

### Compliance Reporting
- Monthly compliance reports on control adherence
- Exception usage and justification reviews
- Automated alerting on policy violations


## Implementation Guidelines

### Deployment Strategy
1. Implement controls gradually with pilot groups
2. Provide training on new requirements
3. Update existing resources to comply with controls
4. Monitor and adjust based on operational feedback

### Testing Requirements
- Test all controls in non-production environments
- Validate exception processes work as designed
- Ensure monitoring and alerting function correctly

## Revision History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | Current | Initial documentation | Cloud Architecture Team |

