# AWS Identity Center Migration - Glossary of Terms

---

## GLOSSARY

**Access Delegations:**
The mappings that connect users or groups to permission sets and AWS accounts, defining who can access what resources.

**Active Directory (AD):**
Microsoft's directory service that stores information about users, computers, and other resources on a network. Used as an identity source for authentication and authorization.

**AD Connector:**
AWS service that acts as a proxy to redirect directory requests to an on-premises Active Directory without caching information in the cloud.

**Attribute Mapping:**
The configuration that defines how user attributes (email, name, groups) from an external identity provider are mapped to corresponding attributes in AWS Identity Center.

**AWS Account:**
A container for AWS resources identified by a unique 12-digit account ID. Each account provides isolated billing, resource management, and security boundaries. Organizations typically use multiple AWS accounts to separate workloads, environments (dev/test/prod), or business units.

**AWS CLI:**
AWS Command Line Interface, a tool for managing AWS services from the command line.

**AWS Identity Center (formerly AWS SSO):**
AWS service that provides single sign-on access to multiple AWS accounts and business applications using a centralized identity source.

**Destructive Operation:**
A process that permanently deletes data without the ability to easily recover or undo the changes.

**External Identity Provider (External IdP):**
A third-party service (like PingOne) that manages user identities and authentication outside of AWS, integrated via SAML or SCIM protocols.

**IAM (Identity and Access Management):**
AWS service for managing access to AWS resources through users, groups, roles, and policies.

**IAM Roles:**
AWS identities with specific permissions that can be assumed by users or services to access AWS resources.

**Identity Source:**
The system that stores and manages user identities for AWS Identity Center. Can be Active Directory, External IdP, or Identity Center directory.

**Member Accounts:**
AWS accounts that are connected to AWS Identity Center and can have permission sets assigned to users.

**Permission Assignments:**
The specific connections between users/groups, permission sets, and AWS accounts that grant access.

**Permission Sets:**
Collections of AWS IAM policies that define what actions users can perform in AWS accounts. These are templates for access that can be assigned to users or groups. 

**PingOne:**
A cloud-based identity-as-a-service (IDaaS) platform that provides authentication, single sign-on, and directory services.

**SAML 2.0 (Security Assertion Markup Language):**
An open standard for exchanging authentication and authorization data between an identity provider and a service provider. Used for single sign-on.

**SCIM 2.0 (System for Cross-domain Identity Management):**
An open standard protocol for automating the exchange of user identity information between identity providers and service providers. Enables automatic user and group provisioning.

**SCIM Endpoint:**
The URL and access point where SCIM requests are sent to synchronize user and group information.

**SCIM Provisioning:**
The automated process of creating, updating, and deleting users and groups in AWS Identity Center based on changes in the external identity provider.

**User Attributes:**
Properties associated with a user account such as email address, first name, last name, and group memberships.

**User Sessions:**
Active authenticated connections between users and AWS services through Identity Center.
