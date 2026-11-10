# Standard Operating Procedure
## AWS API Gateway — Private REST API Creation (Based on AWS Official Documentation)

| Field         | Details                          |
|---------------|----------------------------------|
| **Owner**     | Cloud Operations (CloudOps)      |
| **Audience**  | Development Teams, CloudOps      |
| **Version**   | 1.0                              |
| **Status**    | Draft                            |
| **Region**    | us-west-2 (Oregon)               |
| **Reference** | https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-private-api-create.html |

---

## 1. Purpose

This SOP documents the technical steps for creating a private REST API in AWS API Gateway as defined in the AWS official documentation. It is intended to be used alongside the Globe Life API Gateway SOP (`SOP_APIGateway_PrivateAPI_Creation_and_Update.md`), which defines Globe Life-specific naming conventions, roles, approval processes, and environment promotion procedures.

---

## 2. Overview

A private REST API in API Gateway is accessible only from within your Amazon VPC using an interface VPC Endpoint (VPCE) for `execute-api`. Traffic never leaves the AWS network. To make a private API accessible, you must:

1. Create a VPC Interface Endpoint for `execute-api` in your VPC
2. Create the private REST API
3. Attach a resource policy to control access
4. Deploy the API to a stage

---

## 3. Step 1 — Create a VPC Interface Endpoint for execute-api

A VPC Interface Endpoint must exist in the target VPC before the private API can be invoked. This step is performed by the **Cloud Operations team** at Globe Life via ServiceNow request.

### What CloudOps does:

#### Console
1. Open the **VPC Console** → **Endpoints** → **Create Endpoint**.
2. For **Service category**, select **AWS services**.
3. In the **Service Name** search, find and select `com.amazonaws.us-west-2.execute-api`.
4. Select the target **VPC**.
5. Select the subnets — use only subnets prefixed with `PVT_`.
6. For **Security Group**, select or create a security group that allows HTTPS (port 443) inbound from the VPC CIDR.
7. For **Policy**, leave as **Full Access** (the API resource policy will control access).
8. Click **Create Endpoint**.
9. Note the **VPC Endpoint ID** (`vpce-xxxxxxxxxxxxxxxxx`) — provide this to the requesting development team.

#### CLI
```bash
aws ec2 create-vpc-endpoint \
  --vpc-id <vpc-id> \
  --vpc-endpoint-type Interface \
  --service-name com.amazonaws.us-west-2.execute-api \
  --subnet-ids <pvt-subnet-id-1> <pvt-subnet-id-2> \
  --security-group-ids <sg-id> \
  --private-dns-enabled \
  --region us-west-2 \
  --profile <sso-profile>
```

> **Private DNS:** Enabling private DNS on the endpoint allows you to call the API using the default API Gateway hostname (`<api-id>.execute-api.us-west-2.amazonaws.com`) without needing the VPC Endpoint-specific URL. This is the recommended setting.

---

## 4. Step 2 — Create the Private REST API

### Console
1. Open the **API Gateway Console**.
2. Click **Create API**.
3. Under **REST API**, click **Build**.
4. Select **New API**.
5. Enter an **API name** (follow Globe Life naming conventions — see `SOP_APIGateway_PrivateAPI_Creation_and_Update.md` Section 5).
6. Under **API endpoint type**, select **Private**.
7. In the **VPC Endpoint IDs** field, enter the VPC Endpoint ID provided by CloudOps (`vpce-xxxxxxxxxxxxxxxxx`).
   > You may enter multiple VPC Endpoint IDs if the API needs to be accessible from multiple VPCs.
8. Click **Create API**.

### CLI
```bash
aws apigateway create-rest-api \
  --name "<api-name>" \
  --endpoint-configuration "types=PRIVATE,vpcEndpointIds=<vpce-id>" \
  --region us-west-2 \
  --profile <sso-profile>
```

The response will include the `id` field — this is your `<api-id>` used in all subsequent steps.

```json
{
    "id": "abc1234def",
    "name": "<api-name>",
    "endpointConfiguration": {
        "types": ["PRIVATE"],
        "vpcEndpointIds": ["vpce-xxxxxxxxxxxxxxxxx"]
    }
}
```

---

## 5. Step 3 — Attach a Resource Policy

A resource policy is **required** for private APIs. Without it, all invocations will return `403 Forbidden`. The resource policy defines which VPC Endpoints (and optionally which principals) are allowed to invoke the API.

### Recommended Policy — Restrict to a Single VPC Endpoint

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

> **How this works:** The `Deny` statement explicitly blocks any request not originating from the specified VPC Endpoint. The `Allow` statement then permits all other matching requests. The explicit `Deny` always takes precedence over `Allow` in IAM policy evaluation.

### Alternative Policy — Allow Access from an Entire VPC

Use this if you want to allow access from any endpoint within a specific VPC rather than a specific VPC Endpoint ID:

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
          "aws:sourceVpc": "<vpc-id>"
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

### Attaching the Policy

#### Console
1. In the API Gateway console, select the API.
2. In the left navigation, click **Resource Policy**.
3. Paste the policy JSON.
4. Click **Save**.

#### CLI
```bash
# URL-encode the policy first
# On Windows PowerShell:
$policy = Get-Content -Raw policy.json
$encoded = [System.Uri]::EscapeDataString($policy)

aws apigateway update-rest-api \
  --rest-api-id <api-id> \
  --patch-operations op=replace,path=/policy,value="$encoded" \
  --region us-west-2 \
  --profile <sso-profile>
```

> **Important:** After attaching or modifying the resource policy, you must redeploy the API for the changes to take effect.

---

## 6. Step 4 — Build API Resources and Methods

This step is application-specific. The general process is:

### Console
1. In the API Gateway console, select the API.
2. Under **Resources**, click **Create Resource** to add a path (e.g., `/items`).
   - Optionally enable **CORS** if needed.
3. With the resource selected, click **Create Method**.
4. Select the HTTP method (GET, POST, PUT, DELETE, etc.).
5. Configure the **Integration type** (Lambda, HTTP, AWS Service, VPC Link, or Mock).
6. Click **Save**.
7. Repeat for all required resources and methods.

### CLI — Example: Create a Resource and GET Method with Lambda Integration
```bash
# Get the root resource ID
aws apigateway get-resources \
  --rest-api-id <api-id> \
  --region us-west-2 \
  --profile <sso-profile>

# Create a child resource
aws apigateway create-resource \
  --rest-api-id <api-id> \
  --parent-id <root-resource-id> \
  --path-part "items" \
  --region us-west-2 \
  --profile <sso-profile>

# Create a GET method on the resource (no auth for example)
aws apigateway put-method \
  --rest-api-id <api-id> \
  --resource-id <resource-id> \
  --http-method GET \
  --authorization-type NONE \
  --region us-west-2 \
  --profile <sso-profile>

# Set a Lambda integration
aws apigateway put-integration \
  --rest-api-id <api-id> \
  --resource-id <resource-id> \
  --http-method GET \
  --type AWS_PROXY \
  --integration-http-method POST \
  --uri arn:aws:apigateway:us-west-2:lambda:path/2015-03-31/functions/<lambda-arn>/invocations \
  --region us-west-2 \
  --profile <sso-profile>
```

---

## 7. Step 5 — Deploy the API to a Stage

The API must be deployed to a stage before it can be invoked. A deployment is a snapshot of the API configuration at a point in time.

### Console
1. In the API Gateway console, select the API.
2. Click **Deploy API** from the **Actions** dropdown.
3. Select an existing stage or create a new one (`dev`, `test`, `stage`, or `prod`).
4. Enter a **Deployment description**.
5. Click **Deploy**.

### CLI
```bash
# Create a new stage on first deploy
aws apigateway create-deployment \
  --rest-api-id <api-id> \
  --stage-name <stage> \
  --stage-description "<Stage description>" \
  --description "<Deployment description>" \
  --region us-west-2 \
  --profile <sso-profile>
```

After deployment, the invoke URL format is:

```
https://<api-id>.execute-api.us-west-2.amazonaws.com/<stage>/<resource>
```

Or, if using the VPC Endpoint-specific URL (when private DNS is not enabled):

```
https://<api-id>-<vpce-id>.execute-api.us-west-2.amazonaws.com/<stage>/<resource>
```

---

## 8. Step 6 — Test the Private API

### From within the VPC (or via Transit Gateway)
```bash
curl -X GET \
  https://<api-id>.execute-api.us-west-2.amazonaws.com/<stage>/<resource> \
  -H "x-apigw-api-id: <api-id>"
```

> The `x-apigw-api-id` header is required when private DNS is enabled on the VPC Endpoint and you are calling from within the VPC, to disambiguate which private API to route to.

### Using the AWS Console Test Feature
1. In the API Gateway console, select the API → **Resources**.
2. Select a method.
3. Click the **TEST** button in the method execution panel.
4. Fill in any required parameters and click **Test**.

> **Note:** The console test feature bypasses the resource policy and VPC Endpoint restriction. It is useful for testing integration configuration but does not validate network-level access.

### Expected Results
| Test Location              | Expected Response         |
|----------------------------|---------------------------|
| Inside VPC / Transit GW    | `200 OK` (or expected response) |
| Outside VPC (public internet) | `403 Forbidden`         |

---

## 9. Updating an Existing Private API

When updating a private API, the following rules apply:

- **Resource policy changes** require a redeployment to take effect.
- **Method/integration changes** require a redeployment to take effect.
- **Stage settings** (logging, throttling, caching) take effect immediately without redeployment.
- **Endpoint configuration changes** (e.g., adding/removing VPC Endpoint IDs) can be made via the console under **API Settings** or via CLI:

```bash
aws apigateway update-rest-api \
  --rest-api-id <api-id> \
  --patch-operations \
    op=add,path=/endpointConfiguration/vpcEndpointIds,value=<new-vpce-id> \
  --region us-west-2 \
  --profile <sso-profile>
```

To remove a VPC Endpoint ID:
```bash
aws apigateway update-rest-api \
  --rest-api-id <api-id> \
  --patch-operations \
    op=remove,path=/endpointConfiguration/vpcEndpointIds,value=<vpce-id-to-remove> \
  --region us-west-2 \
  --profile <sso-profile>
```

---

## 10. Key Behaviors and Constraints

| Behavior | Detail |
|----------|--------|
| **Default access** | A private API with no resource policy denies all traffic |
| **Resource policy required** | Must be attached before the API is accessible |
| **Redeployment required** | Any change to resources, methods, or resource policy requires a new deployment |
| **Private DNS** | When enabled on the VPC Endpoint, the standard API Gateway hostname resolves to the private IP of the endpoint |
| **Multiple VPC Endpoints** | A single private API can be associated with multiple VPC Endpoint IDs |
| **Cross-account access** | Supported — the resource policy must explicitly allow the source account or VPC Endpoint |
| **Stage variables** | Supported and can be used to parameterize integration URIs per stage |
| **Custom domain names** | Supported for private APIs using Route 53 private hosted zones |

---

## 11. Related Documents

- Globe Life API Gateway SOP: `SOP_APIGateway_PrivateAPI_Creation_and_Update.md`
- AWS Documentation: https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-private-apis.html
- AWS VPC Endpoint Documentation: https://docs.aws.amazon.com/vpc/latest/privatelink/create-interface-endpoint.html

---

## 12. Revision History

| Version | Date       | Author   | Description   |
|---------|------------|----------|---------------|
| 1.0     | 2025-07-14 | CloudOps | Initial draft |
