# Globe Life : AWS Multi-Account Strategy

---

## 1. Purpose

This document defines the organizational strategy for structuring, governing, and managing AWS accounts across the enterprise. It establishes the principles and criteria used to determine account boundaries, ensuring alignment with operational, security, compliance, and financial objectives.

---

## 2. Guiding Principles

- **Least Privilege by Default** — Each account receives only the permissions required for its designated workload.
- **Blast Radius Containment** — Account boundaries limit the scope of impact from misconfigurations, security incidents, or service disruptions.
- **Quota and Rate Limit Distribution** — Workloads are distributed across accounts to avoid hitting AWS service quotas and API request-rate limits.
- **Billing Transparency** — Account-level separation enables granular cost attribution and chargeback by environment and solution.
- **Operational Consistency** — All accounts are provisioned through AWS Control Tower with standardized guardrails, tagging, and baseline configurations.

---

## 3. Account Segmentation Model

### 3.1 Primary Dimension: Environment (SDLC)

All application workloads are segmented by Software Development Lifecycle (SDLC) stage. Each environment tier is isolated in its own AWS account(s).

| Environment | Purpose | Characteristics |
|---|---|---|
| **Development (DEV)** | Active feature development and experimentation | Relaxed guardrails, developer self-service, no availability or uptime requirements |
| **Test (TST)** | Functional, integration, and regression testing | Controlled access, ephemeral environments, automated teardown |
| **Staging (STG)** | Pre-production validation, performance, and UAT | Production-parity configuration, restricted change windows |
| **Production (PRD)** | Live customer-facing workloads | Strictest guardrails, change management enforced, high availability required |
| **Proof of Concept (POC)** | Experimental validation of new technologies, architectures, or approaches | Time-bounded, no production data permitted, no connectivity to production networks, isolated from standard SDLC environments |
| **Sandbox (SBX)** | Unstructured individual experimentation and skill development | No defined deliverable or outcome required, no production data permitted, no connectivity to production networks, isolated from all other environments |

> Promotion of artifacts between environments follows the approved CI/CD pipeline process.

### 3.2 Secondary Dimension: Solution

Within each environment tier, accounts are further segmented by solution. A solution in this context is intentionally flexible in scope — it may represent a full application, a discrete module or integration layer within a larger platform, or a shared service. A dedicated account (or set of accounts) is provisioned per solution when one or more of the following criteria are met:

- The solution has distinct compliance or regulatory requirements (e.g., PCI-DSS, HIPAA, SOX).
- The solution team requires independent operational autonomy.
- The solution has usage patterns that risk approaching service quota limits or API request-rate limits in a shared account.
- The solution has a separate billing or chargeback owner, or there is a desire to view, track, or control the cost and usage of this solution independently from related solutions regardless of ownership.
- The solution has materially different security posture requirements from peer solutions.

---

## 4. Additional Segmentation Criteria

Beyond environment and solution, the following factors may independently justify account-level separation:

### 4.1 Service Quota and API Rate Limit Distribution

AWS enforces per-account service quotas and API request-rate limits. Accounts are separated when:

- A workload is projected to consume >50% of a default service quota (e.g., EC2 instance limits, Lambda concurrency, VPC limits).
- High-frequency API callers (e.g., automation pipelines, monitoring agents) risk throttling shared workloads.
- Quota increase requests are solution-specific and should not affect peer solutions.

### 4.2 Billing Separation and Cost Attribution

AWS account boundaries are the most reliable unit of financial isolation available in the platform. While resource tagging provides a supplementary layer of cost attribution, it is inherently dependent on consistent human and automation behavior — tags can be omitted, misapplied, or retroactively changed. Account-level separation provides billing boundaries that are enforced by AWS itself, independent of tagging discipline or operational consistency.

**Cost Visibility and Attribution**
- Each AWS account produces its own independent cost and usage report, enabling precise attribution of spend to a specific solution, team, or business unit without post-processing or tag-based aggregation.
- Cost Explorer, AWS Budgets, and Cost Anomaly Detection all operate natively at the account level, providing out-of-the-box visibility without requiring custom tagging taxonomies or data pipeline transformations.
- Shared-account cost allocation requires tag-based splitting, which introduces ambiguity when resources serve multiple workloads, when tags are inconsistently applied, or when untaggable resources (e.g., data transfer, support charges, certain managed service fees) are present.
- Account-level separation eliminates the need to reconcile shared infrastructure costs across teams, reducing the operational burden on FinOps and finance functions.

**Chargeback and Showback**
- Account boundaries enable clean chargeback to internal business units, product teams, or cost centers without requiring complex allocation rules or manual adjustments.
- Showback reporting — providing teams with visibility into their consumption without direct financial transfer — is simplified when each team's workloads are contained within a discrete account.
- In multi-tenant shared accounts, cost ownership disputes between teams are common and difficult to resolve definitively. Account separation eliminates this ambiguity entirely.
- For organizations with external billing relationships (e.g., subsidiaries, joint ventures, or entities with distinct P&L ownership such as ALTiG), account-level separation is the only reliable mechanism for producing auditable, defensible cost statements.

**Budget Governance and Anomaly Detection**
- AWS Budgets can be configured per account with independent thresholds, alert recipients, and automated actions (e.g., applying an SCP to restrict further spend when a budget threshold is breached).
- Cost anomaly detection models are trained on per-account spend patterns. In a shared account, anomalies from one workload can mask or be masked by the normal variance of another, reducing detection sensitivity.
- Budget overruns in one account do not affect the budget posture of peer accounts, enabling teams to operate with financial autonomy without risking organization-wide budget impacts.
- Automated budget enforcement actions — such as restricting EC2 instance launches or disabling non-essential services when spend thresholds are exceeded — can be applied to a single account without impacting other workloads.

**Commitment and Discount Isolation**
- Reserved Instance (RI) and Savings Plan commitments can be scoped to specific accounts or shared selectively across the organization via the management account. Account separation enables deliberate control over which workloads benefit from which commitments.
- Workloads with predictable, stable resource consumption (e.g., production) can carry RI or Savings Plan commitments independently of workloads with variable consumption (e.g., dev, test), preventing commitment waste caused by environment-level variability.
- Enterprise Discount Program (EDP) spend tracking and commitment attainment reporting is cleaner when workloads are separated by account, as spend can be attributed to specific portfolios without allocation approximations.

**Audit and Compliance Reporting**
- Account-level billing data provides an immutable, AWS-generated record of resource consumption that can be used for internal audit, external audit, and regulatory reporting without reliance on self-reported tagging data.
- For workloads subject to cost-related compliance requirements (e.g., government contracts with cost accounting standards, or regulated entities with expense allocation requirements), account-level separation provides the evidentiary standard required by auditors.
- Cost and usage data at the account level is available in AWS Cost and Usage Reports (CUR) with line-item granularity, enabling finance teams to produce accurate financial statements without manual reconciliation.

### 4.3 Blast Radius Limitation

One of the most compelling reasons for account-level separation is the containment of adverse events. In a shared-account model, a single misconfiguration, compromised credential, or runaway process can affect every workload in that account simultaneously. Account boundaries act as hard isolation boundaries that AWS enforces at the infrastructure level — no policy, role, or network configuration can bridge them without an explicit, auditable trust relationship.

Account boundaries are used to contain the impact of the following categories of adverse events:

**IAM and Identity Failures**
- An over-permissioned IAM role or policy in one account cannot be leveraged to access resources in a separate account without an explicit cross-account trust.
- A compromised set of IAM credentials is scoped to the account in which they exist; lateral movement to other accounts requires additional trust relationships that can be independently monitored and revoked.
- Privilege escalation attempts are contained within the account boundary; an attacker who achieves full administrative access in a Dev account gains nothing in Prod without a separate, independently controlled trust path.
- Permission boundary violations or policy misconfigurations affect only the workloads within the impacted account.

**Operational and Automation Failures**
- Runaway automation scripts, misconfigured pipelines, or infrastructure-as-code errors that delete or modify resources are scoped to the account in which they execute.
- A CloudFormation stack deletion, Terraform destroy, or scripted cleanup operation cannot reach resources in adjacent accounts.
- Accidental termination of EC2 instances, deletion of S3 buckets, or removal of database snapshots is contained to the account where the action occurs.
- Rate-limiting and throttling caused by a misbehaving automation process affects only the account generating the API calls, protecting peer workloads from service degradation.

**Security Incidents**
- A security incident declared in a Dev or Test account can be fully isolated — the account can be quarantined by detaching it from the Transit Gateway, revoking cross-account role trust, and applying a deny-all SCP — without impacting production workloads.
- Malware, ransomware, or data exfiltration activity detected in one account cannot propagate to resources in other accounts through AWS service APIs without traversing explicit, logged trust boundaries.
- GuardDuty findings, Security Hub alerts, and incident response actions can be scoped and actioned at the account level without requiring organization-wide changes.
- Forensic investigation and evidence preservation can be performed on a contained account without risk of contaminating other environments.

**Resource Exhaustion and Service Limits**
- AWS service quotas are enforced per account. A workload that exhausts EC2 instance capacity, Lambda concurrency, VPC CIDR space, or S3 request rates in one account does not affect the availability of those services in other accounts.
- A Denial of Service condition — whether externally induced or self-inflicted through a misconfigured load test — is bounded by the account's service limits and cannot consume resources allocated to production workloads in a separate account.
- Cost anomalies caused by resource exhaustion or unexpected scaling events are isolated to the account's billing boundary, enabling faster detection and attribution.

**Data Integrity and Compliance**
- Accidental writes, schema migrations, or data corruption events in a non-production account cannot affect production data stores in a separate account.
- Regulatory audit scope is reduced; a compliance failure or data handling violation in one account does not automatically implicate accounts with separate workloads and data classifications.
- Data residency and sovereignty controls applied at the account level ensure that a misconfiguration in one account's replication or export policy cannot expose data governed by a different regulatory framework.

### 4.4 Compliance and Regulatory Isolation

Workloads subject to specific compliance frameworks are placed in dedicated accounts to:

- Simplify audit scope and evidence collection.
- Apply framework-specific SCPs and Config rules without affecting non-regulated workloads.
- Enforce data residency and sovereignty requirements.

### 4.5 Network and Connectivity Segmentation

Accounts with distinct network trust boundaries are separated to:

- Enforce routing and firewall policy at the account level via Transit Gateway attachments.
- Prevent unintended VPC peering or resource sharing across trust zones.
- Support independent DNS resolution and private hosted zone management.

---

## 5. Agentic AI Account Segmentation Model

Agentic AI workloads follow a distinct account segmentation model that differs from the standard SDLC-by-solution pattern. This separation is required due to the unique operational, security, and governance characteristics of AI agents — including their autonomous action-taking behavior, access to sensitive data domains, potential for unintended cross-domain influence, and the need for independent auditability of agent activity.

### 5.1 Core Principle: Agents Are Not Co-located with Standard Solutions

AI agents must not be deployed into accounts that host standard solutions or other non-agentic workloads. Co-location introduces unacceptable risks:

- An agent operating autonomously within a shared account has implicit access to the same network space, IAM trust boundaries, and resource context as the solutions it shares the account with.
- Agent-initiated API calls, tool invocations, and data access patterns are difficult to attribute and audit when interleaved with standard solution activity in shared CloudTrail logs and cost reports.
- A misbehaving or compromised agent could affect the availability, integrity, or confidentiality of co-located solutions with no account-level boundary to contain the impact.
- Governance controls appropriate for agentic workloads (e.g., restrictions on autonomous outbound calls, model invocation rate limits, data access scope) may conflict with or be incompatible with controls required by standard solutions in the same account.

### 5.2 Segmentation by Business Domain

Agentic AI accounts are provisioned per business domain rather than per individual agent or solution. A domain represents a bounded area of business function within which agents operate and to which their data access and tool permissions are scoped.

Example domains:

| Domain | Description |
|---|---|
| Marketing | Agents performing campaign analysis, content generation, and customer engagement tasks |
| Actuarial | Agents supporting risk modeling, pricing analysis, and statistical computation |
| Legal | Agents performing contract review, compliance research, and regulatory analysis |
| Data Analytics | Agents supporting data pipeline orchestration, reporting, and insight generation |
| Claims | Agents supporting claims intake, fraud detection, and adjudication workflows |

Each domain receives its own dedicated AWS account per SDLC environment tier (Dev, Test, Stage, Prod) within the AI-Workloads OU. This ensures:

- Agent permissions and data access are scoped to the domain boundary at the account level.
- A compromised or misbehaving agent in one domain cannot access data or invoke tools belonging to another domain without traversing an explicit, auditable cross-account trust.
- Cost and usage for agentic workloads are attributable by domain, enabling accurate chargeback to the owning business unit.
- Domain-specific compliance requirements (e.g., Legal agents subject to privilege and confidentiality controls, Actuarial agents subject to model governance requirements) can be enforced via domain-scoped SCPs and IAM policies without affecting other domains.

### 5.3 Centralized AI Shared Services Account

A dedicated AI Shared Services account hosts all platform-level infrastructure that is consumed by agents across all domains. This account is the single point of provisioning and governance for shared agentic platform capabilities, and domain accounts access these services via cross-account role trust with least-privilege scoping.

Services hosted in the AI Shared Services account include:

| Service | Purpose |
|---|---|
| Amazon Bedrock AgentCore Gateway | Centralized entry point for agent invocations; enforces authentication, authorization, and request routing across domains |
| AgentCore Identity | Centralized identity and credential management for agents; issues scoped, short-lived credentials to agents at runtime |
| AgentCore Registry | Central registry of approved agents, versions, and deployment metadata; enforces agent lifecycle governance |
| MCP Servers (Model Context Protocol) | Shared tool and context providers consumed by agents across domains; centrally governed and versioned |
| Shared Tools | Reusable tool implementations (e.g., web search, document retrieval, API connectors) available to authorized agents across domains |

**Governance of the AI Shared Services account:**
- No agent workloads are deployed directly into the Shared Services account; it provides platform infrastructure only.
- All cross-domain access to shared services is mediated through AgentCore Gateway and AgentCore Identity; direct resource access from domain accounts is denied by default.
- Changes to shared services (new tools, MCP server versions, gateway configuration) follow a change management process independent of individual domain release cycles.
- The Shared Services account is subject to the strictest access controls in the AI-Workloads OU; compromise of this account would affect all domains and is treated as a critical severity event.

### 5.4 AI Account Structure Summary

```
AI-Workloads OU
├── AI-SharedServices        (AgentCore Gateway, Identity, Registry, MCP Servers, Shared Tools)
├── AI-Dev                   (All domain agent development environments)
├── AI-Test                  (All domain agent test environments)
├── AI-Stage                 (All domain agent staging environments)
└── AI-Prod
    ├── <Domain>-Marketing   (Production agents scoped to the Marketing domain)
    ├── <Domain>-Actuarial   (Production agents scoped to the Actuarial domain)
    ├── <Domain>-Legal       (Production agents scoped to the Legal domain)
    ├── <Domain>-Analytics   (Production agents scoped to the Data Analytics domain)
    └── <Domain>-...         (Additional domains as required)
```

> The account structure within AI-Dev, AI-Test, and AI-Stage mirrors the domain segmentation of AI-Prod. Domain accounts at non-production tiers are used for agent development, evaluation, and pre-production validation within the appropriate domain boundary.

---

## 6. Organizational Unit (OU) Structure

Accounts are organized within AWS Organizations using the following OU hierarchy. Each top-level OU represents a distinct governance boundary with its own SCP inheritance chain.

```
Root
├── AI-Workloads/           (Dedicated OU for AI and agentic workloads; isolated to enable
│   │                        AI-specific controls, model governance, data access policies,
│   │                        and guardrails not applicable to standard application workloads)
│   ├── AI-Dev              (AI workload development and experimentation accounts)
│   ├── AI-Test             (AI model testing, evaluation, and integration validation)
│   ├── AI-Stage            (Pre-production AI workload validation and UAT)
│   ├── AI-Prod             (Production AI and agentic service accounts)
│   └── AI-SharedServices   (Shared model registries, ML pipelines, and AI platform tooling)
│
├── ALTiG/                  (Dedicated OU for Altig company workloads; separated due to
│   │                        distinct corporate ownership model, independent billing
│   │                        accountability, and operational autonomy requirements that
│   │                        differ from standard enterprise governance)
│   ├── AO-Dev/             (Altig development environment accounts)
│   ├── AO-Test/            (Altig test environment accounts)
│   ├── AO-Stage/           (Altig staging environment accounts)
│   ├── AO-Prod/            (Altig production environment accounts)
│   └── AO-SharedServices/  (Altig shared tooling and platform services)
│
├── CICD/                   (CI/CD pipeline tooling accounts; hosts build systems, artifact
│   │                        repositories, deployment automation, and pipeline orchestration.
│   │                        Accounts here have cross-environment deployment permissions
│   │                        governed by strict role trust policies)
│
├── Core/                   (Foundation accounts managed by Cloud Operations;
│   │                        includes the Management account, Log Archive, Audit, and
│   │                        Security tooling accounts provisioned by Control Tower)
│
├── Dev/                    (Standard corporate development accounts for general application
│   │                        workloads; relaxed guardrails, developer self-service enabled)
│
├── Test/                   (Standard corporate test accounts; controlled access,
│   │                        ephemeral environments, automated teardown supported)
│
├── Stage/                  (Standard corporate staging accounts; production-parity
│   │                        configuration, restricted change windows enforced)
│
├── Prod/                   (Standard corporate production accounts; strictest guardrails,
│   │                        change management enforced, high availability required)
│
├── Shared_Services/        (Enterprise shared platform services consumed across OUs;
│   │                        includes centralized networking, DNS, monitoring, and
│   │                        security tooling such as Transit Gateway and Security Hub)
│
├── Sandbox/                (Isolated experimentation accounts; no production data permitted,
│   │                        no connectivity to production networks, time-bounded access)
│
├── Suspended/              (Accounts pending decommission; all workloads removed,
│   │                        SCPs deny all actions except those required for closure)
│
└── Unmanaged/              (Accounts not yet onboarded to Control Tower governance;
                             subject to remediation or migration to an appropriate OU.
                             Treated as untrusted; no cross-account trust relationships
                             permitted until fully onboarded)
```

### 6.1 OU Governance Notes

- **AI-Workloads** and **ALTiG** are intentionally top-level OUs to ensure their SCP inheritance chains are fully independent from standard corporate workload OUs. This prevents accidental policy bleed-through in either direction.
- **CICD** accounts are granted scoped cross-environment deployment permissions via IAM role trust policies, not via SCP exceptions. No human interactive access is permitted in CICD accounts.
- **Unmanaged** accounts are reviewed quarterly. Accounts remaining unmanaged for more than 90 days are escalated to Cloud Operations for disposition.

---

## 7. Account Provisioning Standards

All accounts must be provisioned through AWS Control Tower Account Factory and must meet the following baseline requirements before workloads are deployed:

| Requirement | Implementation |
|---|---|
| Centralized logging | CloudTrail and Config logs forwarded to the Security account S3 bucket |
| Security monitoring | GuardDuty and Security Hub enrolled in the delegated admin aggregator |
| IAM baseline | `AWSControlTowerExecution` role present; permission boundaries applied |
| Tagging | Mandatory tags: `Environment`, `Solution`, `Owner`, `Project` |
| Password policy | Enforced via automation at account provisioning time |
| Root credentials | Root MFA enforced; root access keys removed |
| SCP inheritance | Account inherits OU-level SCPs; no SCP exceptions without CAB approval |

---

## 8. Service Control Policy (SCP) Framework

SCPs are applied at the Root and OU level to enforce non-negotiable guardrails. Root-level SCPs are inherited by every account in the organization. OU-level SCPs are additive and apply only to accounts within that OU and its children.

### 8.1 Root-Level SCPs (Inherited by All OUs)

The following SCPs are attached directly to the Root and apply universally across the organization:

| SCP Name | Managed By | Purpose |
|---|---|---|
| `AWSControlTower-CUSTOM-Deny-T2-GP2` | Custom | Denies creation of T2 EC2 instance types and GP2 EBS volumes; enforces use of current-generation compute and storage |
| `AWSControlTower-Custom-RegionDenyControl` | Custom | Denies API actions in unapproved AWS regions; restricts all workloads to the organization's approved region set |
| `GR-IdentityCenter_RestrictInstanceCreation` | Custom | Controls where new AWS IAM Identity Center instances can be created; prevents unauthorized Identity Center deployments outside the designated home region |
| `AWSControlTower-Custom-Lambda-PublicUrlProtection` | Custom | Denies creation of Lambda function URLs with public (unauthenticated) access; all Lambda URLs must require IAM authentication |
| `AWSControlTower-Custom-EntManagedBoundaryControl` | Custom | Protects enterprise-managed IAM permission boundary policy resources (`Boundary_Ent-*`) from modification or deletion by non-authorized principals |
| `GR-AWSBackupVaultLock-Restriction` | Custom | Denies the ability to add or remove AWS Backup Vault Lock to all but a specific list of authorized roles |
| `FullAWSAccess` | AWS Managed | Baseline allow policy required by AWS Organizations; effective permissions are constrained by all Deny SCPs above |

### 8.2 OU-Level SCPs

The following SCPs are attached directly to specific OUs and are additive to the Root-level SCPs. Control Tower managed guardrail policies (`aws-guardrails-*`) are automatically attached and managed by Control Tower; they must not be manually modified or detached.

| SCP Name | Scope | Managed By | Purpose |
|---|---|---|---|
| `AWSControlTower-CUSTOM-Deny-T2-GP2` | SandBox OU | Custom | Directly attached to SandBox in addition to Root inheritance; reinforces instance and storage type restrictions for sandbox workloads |
| `aws-guardrails-THjmNo` | ALTiG OU | Control Tower | Control Tower managed guardrails applied to the ALTiG OU |
| `aws-guardrails-SXsVFE` | AI-Workloads OU | Control Tower | Control Tower managed guardrails applied to the AI-Workloads OU |
| `aws-guardrails-YbTHzS` | Test OU | Control Tower | Control Tower managed guardrails applied to the Test OU |
| `aws-guardrails-eRgZeE` | Prod OU | Control Tower | Control Tower managed guardrails applied to the Prod OU |
| `aws-guardrails-qFiZNb` | Shared_Services OU | Control Tower | Control Tower managed guardrails applied to the Shared_Services OU |
| `aws-guardrails-PYDSWi` | SandBox OU | Control Tower | Control Tower managed guardrails applied to the SandBox OU |
| `aws-guardrails-khqyvP` | CICD OU | Control Tower | Control Tower managed guardrails applied to the CICD OU |
| `aws-guardrails-fXYOyA` | Core OU | Control Tower | Control Tower managed guardrails applied to the Core OU |
| `aws-guardrails-ydEDPU` | Core OU | Control Tower | Control Tower managed guardrails applied to the Core OU |
| `aws-guardrails-KenNcu` | Dev OU | Control Tower | Control Tower managed guardrails applied to the Dev OU |
| `aws-guardrails-eoecqn` | Stage OU | Control Tower | Control Tower managed guardrails applied to the Stage OU |

> Control Tower managed guardrail policies must only be modified through the AWS Control Tower console.

---

## 9. Access Management

- All human access is provisioned through AWS IAM Identity Center (SSO) using AD group-to-permission-set mappings.
- No long-term IAM user credentials are issued for human access.
- Cross-account automation uses IAM roles with scoped trust policies; credentials are assumed via `sts:AssumeRole`.
- Permission boundaries (`Boundary_Ent-*`) are applied to all customer-managed roles to prevent privilege escalation.

---

## 10. Account Naming Convention

Account names follow a `<PREFIX>_<SolutionName>` pattern, where the prefix identifies the environment or functional category. The underscore (`_`) is the standard delimiter. Solution names use PascalCase with no spaces.

### 10.1 Standard Environment Prefixes

The following prefixes are the approved standard for all new accounts:

| Prefix | Environment | OU |
|---|---|---|
| `DEV_` | Development | Dev OU |
| `TST_` | Test | Test OU |
| `STG_` | Staging | Stage OU |
| `PRD_` | Production | Prod OU |
| `CICD_` | CI/CD Pipeline | CICD OU |
| `SBX_` | Sandbox | SandBox OU |

Examples:
```
DEV_ClaimsFraudProcess
TST_BankAccountVerification
STG_ProducerLifeCycleManagement
PRD_OIPA-Integration
CICD_eServiceCenter
```

### 10.2 Observed Secondary Prefixes

The following prefixes exist in the current account inventory and represent special-purpose or transitional environments. New accounts using these prefixes require Cloud Operations approval:

| Prefix | Purpose | Notes |
|---|---|---|
| `SIT_` | System Integration Testing | Pre-production integration validation; distinct from TST |
| `PPD_` | Pre-Production | Used where a distinct pre-prod tier exists beyond Stage |
| `BFX_` | Bug Fix | Isolated environment for targeted defect remediation |
| `CNV_` | Conversion | Data conversion and migration workloads |
| `POC_` | Proof of Concept | Experimental; time-bounded; no production data permitted |

### 10.3 Shared and Platform Account Naming

Accounts that are not tied to a single SDLC environment use a `<Function>_<Description>` or `<Name>_<Function>` pattern without an environment prefix:

```
Network_MonitoringServices
Network_Security
Globe_CentralObservability
Identity_Services
Architecture_Governance
```

### 10.4 ALTiG Account Naming

Accounts under the ALTiG OU follow the same `<PREFIX>_<SolutionName>` convention but may use the `AO_` identifier to distinguish Altig-owned workloads where cross-portfolio clarity is required.

### 10.5 Naming Anti-Patterns to Avoid

The following patterns exist in the current inventory and must not be used for new accounts:

| Anti-Pattern | Example | Issue |
|---|---|---|
| Spaces in name | `GLOCA Marketing - Dev - ssingh` | Not compatible with automation and tagging tooling |
| Personal identifiers | `GLOCA Marketing - Dev - uissxveeraballi` | Accounts are organizational assets, not personal |
| Reversed env suffix | `CDM_Dev`, `CDM_Prod` | Inconsistent with the standard `PREFIX_Solution` order |
| Numeric sandbox names | `Sandbox_1`, `Sandbox_2` | Provides no context about purpose or owner |

Existing non-conforming accounts should be renamed as part of the next scheduled account governance review.

---

## 11. Account Segmentation Exception Request Process

The default position of this strategy is that any deployment which triggers one or more segmentation criteria warrants a dedicated AWS account. An exception is a deliberate, justified architectural decision to co-deploy into an existing account despite one or more criteria being met. Exceptions are not a routine path and must be formally requested, justified, and approved before co-deployment proceeds.

An exception to this strategy is distinct from a security policy exception. No security policies are violated by co-deployment; however, co-deploying into an existing account inherently widens the blast radius of any adverse event affecting that account, and the requestor must explicitly acknowledge and accept that consequence.

### Insufficient Justifications

The following justifications, whether stated explicitly or implied, will not be accepted as a basis for an exception. Submitting a request grounded primarily in any of the following will result in the request being returned without approval.

**Operational Convenience**
- A single account is simpler to manage.
- We do not want to manage multiple accounts.
- It is faster to deploy into an existing account.
- Our team does not have experience managing multiple accounts.

**Timeline Pressure**
- We do not have time to provision a new account before our delivery deadline.
- A new account would delay our project timeline.

> Timeline constraints do not waive the requirement for a dedicated account. Expedited account provisioning options may be available but should not be relied upon as a substitute for planning account needs ahead of delivery timelines.

**Minimization of Criteria**
- The criteria technically apply but are not considered material in our case.
- The blast radius impact is low because the deployment is small.
- The two solutions are closely related, so co-location makes sense.

> The segmentation criteria exist precisely because these assessments are difficult to make accurately at the time of deployment. A deployment that appears small or low-risk at inception may grow in scope, sensitivity, or usage patterns over time. Co-location decisions are difficult to reverse once a solution is established in an account.

**Precedent**
- Other teams have co-deployed without an exception.
- This is how we have always done it.

---

### 11.1 Request Identification

The requestor must provide the following identifying information:

| Field | Description |
|---|---|
| Requestor Name | Full name of the individual submitting the request |
| Date of Request | Date the exception request is submitted |
| Solution Name | Name of the solution or deployment being proposed |
| Target Account(s) | Name and ID of the existing account(s) requested for co-deployment |
| SDLC Environment | The environment tier involved (Dev, Test, Stage, Prod) |

### 11.2 Criteria Findings

The requestor must identify which segmentation criteria were triggered by their deployment and provide a specific statement for each triggered criterion explaining why co-deployment is considered acceptable despite it being met. A blanket assertion that the criteria are not material is not sufficient — each triggered criterion must be addressed individually.

The requestor is not disputing that the criteria were met. They are making an architectural argument that the specific circumstances of this deployment make co-deployment into the existing account reasonable despite the criteria being met.

| Criterion | Triggered (Yes/No) | Requestor Justification for Co-deployment |
|---|---|---|
| The deployment includes data which requires isolation due to its classification, sensitivity, regulatory obligations, or access patterns that differ from those of the existing solution in the target account | | |
| The team managing this deployment is different from the team managing the existing solution in the target account, creating distinct operational ownership, change management, or access control requirements | | |
| This deployment is projected to generate resource consumption that risks approaching service quota limits or API request-rate limits in the target account, which could degrade the availability or performance of the existing solution | | |
| This deployment has a security profile that requires its own dedicated security controls, guardrails, or IAM boundaries that are distinct from or incompatible with those applied to the existing solution in the target account | | |
| This deployment requires billing isolation so that its cost and usage can be tracked, attributed, or charged back independently from the existing solution, and reliance on tagging alone is insufficient to meet that requirement | | |
| Co-deploying into the existing account widens the blast radius of any adverse event — including security incidents, credential compromise, runaway automation, accidental resource deletion, service quota exhaustion, or operational failures — such that an event affecting one deployment could impact the other | | |

### 11.3 Co-deployment Justification

The requestor must provide a clear architectural argument for why the existing account is an appropriate host for the new deployment. This justification must address:

- The functional and architectural relationship between the new deployment and the existing solution already hosted in the target account
- Why the triggered criteria, in the context of this specific pairing of deployments, do not present an unacceptable operational risk
- How the two deployments will be logically separated within the shared account, including tagging strategy, resource naming conventions, IAM boundary enforcement, and network segmentation where applicable

### 11.4 Blast Radius Acknowledgment

Regardless of which criteria were triggered, all exception requests must include an explicit acknowledgment of the following:

> *By co-deploying into an existing account, the blast radius of any adverse event affecting that account — including but not limited to security incidents, credential compromise, runaway automation, accidental resource deletion, and service quota exhaustion — is widened to include both the existing solution and the new deployment. This is an accepted architectural consequence of this exception request. The undersigned acknowledge this risk on behalf of their team and business unit.*

This acknowledgment must be signed by:
- The requestor
- The requestor's product owner or business unit leader

This is not a security policy acceptance. It is a statement of informed architectural consent.

### 11.5 Approval

All exception requests require approval from both of the following before co-deployment may proceed:

| Approver | Role | Scope |
|---|---|---|
| IDD - Cloud Architecture | Infrastructure Cloud Architect | Reviews the architectural justification and co-deployment approach for alignment with the overall account strategy |
| IT Security Architect | Security Architecture | Reviews the blast radius acknowledgment and criteria findings to confirm no security policies are implicated and the risk acceptance is appropriate |

Approval from both parties is required for all exceptions without exception. Neither approver may delegate this approval to another party.

---

## 12. Governance and Review

| Activity | Frequency | Owner |
|---|---|---|
| Account inventory review | TBD (Quarterly suggested) | Cloud Operations |
| SCP effectiveness review | TBD (Semi-annually suggested) | Security Architecture |
| Cost attribution validation | TBD (Monthly suggested) | FinOps / Cloud Finance |
| Unused account decommission | TBD (Quarterly suggested) | Cloud Operations |
| New account request approval | TBD (On-demand suggested) | IDD - Cloud Architecture |

---

## 13. Related Documents and Resources

- AWS Well-Architected Framework — [Organizing Your AWS Environment](https://docs.aws.amazon.com/whitepapers/latest/organizing-your-aws-environment/organizing-your-aws-environment.html)
- AWS Well-Architected Framework — [Design Principles for Your Multi-Account Strategy](https://docs.aws.amazon.com/whitepapers/latest/organizing-your-aws-environment/design-principles-for-your-multi-account-strategy.html)
- AWS Documentation — [AWS Organizations SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
- AWS Documentation — [AWS Control Tower](https://docs.aws.amazon.com/controltower/latest/userguide/what-is-control-tower.html)
- AWS Documentation — [IAM Identity Center](https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html)

---

## 14. Document Control

| Field | Detail |
|---|---|
| **Version** | 1.0 |
| **Status** | Draft |
| **Owner** | I.T. Design & Delivery - Cloud Architecture |
| **Author** | Scott Walls |
