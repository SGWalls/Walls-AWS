# Standard Operating Procedure
## AWS API Gateway — Private REST API Creation and Update

| Field         | Details                          |
|---------------|----------------------------------|
| **Owner**     | Cloud Operations (CloudOps)      |
| **Audience**  | Development Teams, CloudOps      |
| **Version**   | 1.0                              |
| **Status**    | Draft                            |
| **Region**    | us-west-2 (Oregon)               |

---

## 1. Purpose

This SOP defines the process for creating and updating a private REST API in AWS API Gateway within Globe Life's AWS environment. It establishes the required steps, responsibilities, and guardrails to ensure APIs are deployed securely and consistently across all application accounts.

---

## 2. Scope

This procedure applies to all Globe Life development teams deploying REST APIs in AWS API Gateway. It covers:

- Creation of a new private REST API via the AWS Console or AWS CLI
- Updating an existing private REST API
- Requesting a public (Regional or Edge-optimized) API, which requires Network Security and CloudOps involvement

This SOP does **not** cover CDK-based deployments (covered separately) or HTTP/WebSocket API types.

---

## 3. Roles and Responsibilities

| Role                    | Responsibility                                                                                  |
|-------------------------|-------------------------------------------------------------------------------------------------|
| **Development Team**    | Create and update private REST APIs; submit ServiceNow requests for VPC Endpoints and public APIs |
| **Peer Reviewer**       | Review API configuration and resource policy before deployment to higher environments           |
| **Cloud Operations**    | Create VPC Interface Endpoints upon request; convert APIs to public type upon approval          |
| **Network Security**    | Review and approve requests for public (Regional or Edge-optimized) APIs                        |

---

## 4. Prerequisites

Before creating a private API, confirm the following are in place:

- [ ] You have AWS Console or CLI access to the target account (e.g., `DEV_ApplicationName`)
- [ ] Your IAM permissions include `apigateway:POST`, `apigateway:PUT`, `apigateway:PATCH`, and `apigateway:GET`
- [ ] A VPC Interface Endpoint for `execute-api` exists in the target account's VPC, hosted in subnets prefixed with `PVT_`
  - If no endpoint exists, submit a ServiceNow request to CloudOps (see Section 7)
- [ ] You know the VPC Endpoint ID (`vpce-xxxxxxxxxxxxxxxxx`) for the target account
- [ ] A CloudWatch Log Group has been created or identified for API access logging

---

## 5. Naming Conventions

| Resource              | Convention                                                                 | Example                              |
|-----------------------|----------------------------------------------------------------------------|--------------------------------------|
| API Name              | `<AppName>-<Purpose>-api`                                                  | `ClaimsPortal-Submissions-api`       |
| Stage Name            | Environment abbreviation: `dev`, `test`, `stage`, `prod`                  | `prod`                               |
| CloudWatch Log Group  | `/aws/apigateway/<AppName>-<Purpose>-api/<stage>`                          | `/aws/apigateway/ClaimsPortal-Submissions-api/prod` |
| VPC Endpoint          | Managed by CloudOps; hosted in `PVT_` subnets                             | —                                    |

---

## 6. Procedure

### 6.1 Create a Private REST API

#### Option A — AWS Console

1. Sign in to the AWS Console for the target account (e.g., `DEV_ApplicationName`).
2. Navigate to **API Gateway** → **APIs** → **Create API**.
3. Select **REST API** → **Build**.
4. Under **API endpoint type**, select **Private**.
5. Enter the **API name** following the naming convention in Section 5.
6. Click **Create API**.
7. Attach a **Resource Policy** immediately after creation (see Section 6.3 — this is required before the API is accessible).
8. Build your resources and methods as needed.
9. Enable CloudWatch logging (see Section 6.4).
10. Deploy the API to the appropriate stage (see Section 6.5).

#### Option B — AWS CLI

```bash
# Step 1: Create the private REST API
aws apigateway create-rest-api \
  --name "<AppName>-<Purpose>-api" \
  --endpoint-configuration "types=PRIVATE,vpcEndpointIds=<vpce-id>" \
  --region us-west-2 \
  --profile <sso-profile>

# Note the returned "id" value — this is your <api-id>

# Step 2: Attach the resource policy (see Section 6.3 for policy content)
aws apigateway update-rest-api \
  --rest-api-id <api-id> \
  --patch-operations \
    op=replace,path=/policy,value='<url-encoded-resource-policy>' \
  --region us-west-2 \
  --profile <sso-profile>
```

> **Note:** The resource policy value must be URL-encoded when passed via CLI. Use `python3 -c "import urllib.parse, sys; print(urllib.parse.quote(sys.stdin.read()))"` to encode your policy JSON.

---

### 6.2 Update an Existing Private REST API

#### Console

1. Navigate to **API Gateway** → **APIs** → select the target API.
2. Make the required changes to resources, methods, integrations, or settings.
3. Have changes peer reviewed by a team member before deploying.
4. Deploy to the appropriate stage (see Section 6.5).

#### CLI

```bash
# Update an existing resource or method — example: update integration URI
aws apigateway put-integration \
  --rest-api-id <api-id> \
  --resource-id <resource-id> \
  --http-method <METHOD> \
  --type <integration-type> \
  --uri <integration-uri> \
  --region us-west-2 \
  --profile <sso-profile>
```

---

### 6.3 Resource Policy (Required for Private APIs)

All private APIs **must** have a resource policy attached that restricts access to the designated VPC Endpoint. Without this policy, the API will return `403 Forbidden` even from within the VPC.

Use the following template, replacing placeholder values:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Principal": "*",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:us-west-2:<account-id>:<api-id>/*",
      "Condition": {
        "StringNotEquals": {
          "aws:sourceVpce": "<vpce-id>"
        }
      }
    },
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "execute-api:Invoke",
      "Resource": "arn:aws:execute-api:us-west-2:<account-id>:<api-id>/*"
    }
  ]
}
```

> **Important:** The `Deny` statement must come before the `Allow` statement. The Deny explicitly blocks any invocation not originating from the designated VPC Endpoint.

After attaching or updating the resource policy, you **must redeploy** the API to the stage for the policy to take effect.

---

### 6.4 Enable CloudWatch Logging

#### Console

1. In the API Gateway console, go to **Stages** → select the stage.
2. Under the **Logs/Tracing** tab:
   - Set **CloudWatch Logs** to **Errors and Info Logs** (or **Full Request and Response Logs** for non-production).
   - Enter the ARN of the CloudWatch Log Group following the naming convention in Section 5.
3. Save changes.

#### CLI

```bash
# Create the log group first if it doesn't exist
aws logs create-log-group \
  --log-group-name "/aws/apigateway/<AppName>-<Purpose>-api/<stage>" \
  --region us-west-2 \
  --profile <sso-profile>

# Update stage settings to enable logging
aws apigateway update-stage \
  --rest-api-id <api-id> \
  --stage-name <stage> \
  --patch-operations \
    op=replace,path=/*/*/logging/loglevel,value=INFO \
    op=replace,path=/accessLogSettings/destinationArn,value=arn:aws:logs:us-west-2:<account-id>:log-group:/aws/apigateway/<AppName>-<Purpose>-api/<stage> \
  --region us-west-2 \
  --profile <sso-profile>
```

> **Note:** The API Gateway account-level CloudWatch role ARN must be configured in the account for logging to work. If you receive an error about CloudWatch Logs role ARN, contact CloudOps to configure the account-level setting.

---

### 6.5 Deploy the API to a Stage

#### Console

1. In the API Gateway console, select the API.
2. Click **Deploy API** from the **Actions** menu (or the **Deploy** button).
3. Select the target **Stage** (`dev`, `test`, `stage`, or `prod`).
4. Add a deployment description noting what changed.
5. Click **Deploy**.

#### CLI

```bash
aws apigateway create-deployment \
  --rest-api-id <api-id> \
  --stage-name <stage> \
  --description "<Brief description of change>" \
  --region us-west-2 \
  --profile <sso-profile>
```

---

### 6.6 Promote to Higher Environments

| From → To         | Action Required                                                                 |
|-------------------|---------------------------------------------------------------------------------|
| `dev` → `test`    | Peer review by development team; redeploy in `TST_ApplicationName` account      |
| `test` → `stage`  | Peer review; redeploy in `STG_ApplicationName` account                          |
| `stage` → `prod`  | Peer review; redeploy in `PRD_ApplicationName` account                          |

Each account has its own VPC and VPC Endpoint. Update the resource policy with the correct `<vpce-id>` and `<account-id>` for each target account before deploying.

---

## 7. Requesting a VPC Interface Endpoint (execute-api)

If the target account does not have a VPC Interface Endpoint for `execute-api`:

1. Submit a **ServiceNow request** to the Cloud Operations team.
2. Include the following in the request:
   - Target AWS Account ID and Name (e.g., `DEV_ApplicationName`)
   - VPC ID
   - Subnet names prefixed with `PVT_` to host the endpoint
   - Requested service: `com.amazonaws.us-west-2.execute-api`
3. CloudOps will create the endpoint and provide the VPC Endpoint ID (`vpce-xxxxxxxxxxxxxxxxx`).
4. Use the returned Endpoint ID in your API resource policy (Section 6.3).

---

## 8. Requesting a Public API (Regional or Edge-Optimized)

Public APIs are **not permitted** without prior approval. If a public API is required:

1. Submit a **ServiceNow request** to the Network Security team with:
   - Business justification for a public endpoint
   - Application name and AWS account
   - Intended consumers of the API
2. Network Security will review and approve or deny the request.
3. Upon approval, CloudOps will convert the API endpoint type to Regional or Edge-Optimized.
4. The development team will be granted update access to that specific API.

> **Do not** attempt to change the endpoint type of an existing private API without going through this process. IAM permissions for development teams restrict API creation to private endpoint types only.

---

## 9. Verification

After creation or update, verify the following:

- [ ] API endpoint type is **Private** (confirm in Console under API Settings)
- [ ] Resource policy is attached and contains the correct VPC Endpoint ID and account ID
- [ ] API has been deployed to the target stage
- [ ] CloudWatch Log Group exists and is receiving logs after a test invocation
- [ ] A test invocation from within the VPC (or via Transit Gateway) returns the expected response
- [ ] A test invocation from outside the VPC returns `403 Forbidden`

---

## 10. Rollback

If a deployment causes issues:

#### Console
1. Navigate to **API Gateway** → **Stages** → select the stage.
2. Under the **Deployment History** tab, select the previous deployment.
3. Click **Set as Active Deployment**.

#### CLI
```bash
# List deployments to find the previous deployment ID
aws apigateway get-deployments \
  --rest-api-id <api-id> \
  --region us-west-2 \
  --profile <sso-profile>

# Roll back by updating the stage to point to the previous deployment
aws apigateway update-stage \
  --rest-api-id <api-id> \
  --stage-name <stage> \
  --patch-operations op=replace,path=/deploymentId,value=<previous-deployment-id> \
  --region us-west-2 \
  --profile <sso-profile>
```

---

## 11. Related Resources

- [AWS API Gateway Private API Documentation](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-private-apis.html)
- [VPC Endpoint Policies for API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-vpc-endpoint-policies.html)
- ServiceNow — Cloud Operations Request: `[Internal ServiceNow Link]`
- ServiceNow — Network Security Request: `[Internal ServiceNow Link]`

---

## 12. Revision History

| Version | Date       | Author       | Description     |
|---------|------------|--------------|-----------------|
| 1.0     | 2025-07-14 | CloudOps     | Initial draft   |
