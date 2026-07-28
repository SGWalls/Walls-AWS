# AWS Identity Center Identity Source Migration: AD Connector to PingOne External IdP

---

## EXECUTIVE SUMMARY

Migrating AWS Identity Center's Identity Source from Active Directory to PingOne as an external identity provider is a destructive operation.  All users, groups, and permission assignments within Identity Center will be deleted when the identity source is changed. All access assignments must be redeployed after migration.

Business Impact:
All users will lose AWS access to the console through AWS Identity Center during the migration window. All of the mappings of Groups to Permission Sets to AWS Acccounts (otherwise refered to as access delegations) must be manually reassigned. This is effectively a one-way migration as reverting back to AD Connector requires repeating the same destructive process. 

---

## WHAT GETS DELETED VS. PRESERVED

- Permanently Deleted:  
  - All users in the AWS Identity Center directory.
  - All groups in the Identity Center directory.
  - All permission assignments (which users/groups can access which AWS accounts with which permissions).
  - All active user sessions will be deleted.

- Preserved:
  - Permission sets (the actual policies defining what access is granted).
  - AWS member account connections to Identity Center.
  - IAM roles in member accounts (though no users can use them until reassigned) will be preserved.

- **Critical Understanding:** 
  - The permission policies remain, but all assignments of those policies to Groups are deleted. 

---

## MIGRATION OVERVIEW

### Phase 1: Preparation 

Objective: Capture current state and prepare for recreation

Key Activities:  
- Export complete inventory of users, groups, and all permission assignments.  
- Configure PingOne tenant with SAML and SCIM integration for AWS.  
- Migrate user and group data to PingOne.  
- Develop automation scripts to recreate permission assignments.  
- Execute full test migration in non-production environment.  
- Create communication plan for user notification.  

Deliverables:  
- Complete export of current access configuration.  
- Fully configured PingOne SAML and SCIM integrations.  
- Tested automation scripts for assignment recreation.  
- Documented rollback considerations.  

### Phase 2: Migration Execution 

Objective: Switch identity source and restore user access

Key Activities:  
- Change Identity Center identity source to PingOne (triggers deletion of all users/groups/assignments).  
- Enable SCIM provisioning to sync users and groups from PingOne to Identity Center.  
- Execute automation scripts to recreate all permission set assignments.  
- Validate access for critical users and applications.  

Expected Downtime: All users will be unable to access AWS accounts through AWS Identity Center during this window.

### Phase 3: Post-Migration 

Objective: Validate access and resolve issues

Key Activities:  
- Systematic validation of user authentication and access.  
- Troubleshoot individual access issues.  
- Update internal documentation and access request procedures.  
- Monitor for authentication or authorization problems.  

---

## TECHNICAL REQUIREMENTS

PingOne Side:  
- SAML 2.0 integration configured for AWS Identity Center.  
- SCIM 2.0 provisioning enabled to automatically sync users and groups to AWS Identity Center.  
- User attributes properly mapped (email, name, group memberships, userprincipalname).  

AWS Side:  
- SCIM endpoint enabled in Identity Center.  
- Automation capability (AWS CLI/SDK) to bulk-recreate permission assignments.  
- Export of current configuration before migration.  

Tooling:  
- Scripts to export current users, groups, and assignments.  
- Scripts to bulk-recreate assignments after migration.  

---

## RISKS AND MITIGATION

Extended downtime if assignment recreation fails (High Impact):  
Mitigation: Develop and test automation scripts in advance; have manual process documented.

Users unable to access critical systems (High Impact):  
Mitigation: Schedule migration during low-usage period; prioritize critical user validation.

Incomplete or inaccurate assignment recreation (Medium Impact):  
Mitigation: Thorough validation of the exported configuration data.

Automation script failures due to API throttling (Medium Impact):  
Mitigation: Implement exponential backoff and retry logic in assignment recreation scripts; consider batching assignments to stay within AWS API rate limits.

Orphaned IAM roles in member accounts (Low Impact):  
Mitigation: Document all Identity Center-created roles; plan cleanup of unused roles post-migration if assignment structure changes.

---

## DECISION POINTS

Before Proceeding:  
- What is the total number of users and permission assignments to recreate?  
- What is the acceptable maintenance window for your organization?  
- Which users/applications are critical and must be validated first?  
- Who will be responsible for executing the migration and assignment recreation?  
- What is the communication plan for affected users?  

Success Criteria:  
- All users can authenticate via PingOne.  
- All permission assignments accurately recreated.  
- AWS Console and CLI access functional.  
- Zero unintended access gaps or privilege escalations.  

