Subject: AWS Identity Center Migration: AD Connector to PingOne External IdP

---

BLUF (BOTTOM LINE UP FRONT)

Migrating AWS Identity Center from AD Connector to PingOne External IdP will delete all users, groups, and permission assignments. All user access to AWS will be lost during migration and must be manually recreated. This is a one-way destructive operation requiring 2-4 weeks preparation, a 4-8 hour maintenance window, and 1-2 weeks validation. Non-production testing is mandatory before production execution.

---

RECOMMENDATION

Do not proceed with production migration until a complete test migration has been successfully executed in a non-production environment.

---

KEY FACTS

Deleted During Migration: All users, all groups, all permission assignments (group-to-permission-to-account mappings), all active sessions.

Preserved During Migration: Permission sets (policies), AWS account connections, IAM roles (unusable until reassigned).

User Impact: Complete loss of AWS console access during migration window. No ability to authenticate until assignments are recreated.

Rollback: Equally destructive. Switching back to AD Connector deletes everything again.

---

CRITICAL REQUIREMENTS FOR SUCCESS

Before Migration: Export all users, groups, and assignments. Configure PingOne with SAML and SCIM. Develop and test automation scripts for assignment recreation. Complete non-production test migration.

During Migration: Change identity source (triggers deletion). Enable SCIM sync. Execute automation to recreate all assignments. Validate critical user access.

After Migration: Validate all user authentication and access. Resolve issues. Update documentation.

---

HIGH-RISK AREAS

Assignment recreation automation fails causing extended downtime.
Critical users unable to access systems during or after migration.
Incomplete or inaccurate assignment recreation causing access gaps.
No viable rollback option without repeating destructive process.

Mitigation: Test automation thoroughly in non-production. Schedule during low-usage period. Validate exports before migration. Ensure PingOne is fully configured and tested.

---

DECISION REQUIRED

Approve non-production test migration to validate process, automation, and timeline before committing to production migration.

---

QUESTIONS REQUIRING ANSWERS

How many users and permission assignments must be recreated?
What is the acceptable maintenance window duration?
Which users and applications are critical for immediate validation?
Who will execute the migration and assignment recreation?
What is the user communication and notification plan?

---

NEXT ACTIONS IF APPROVED

Develop export and automation scripts.
Schedule and execute non-production test migration.
Create production migration runbook based on test results.
Coordinate production maintenance window.
Prepare user communication materials.
