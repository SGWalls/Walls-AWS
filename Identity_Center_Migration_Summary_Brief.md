Subject: AWS Identity Center Migration: AD Connector to PingOne External IdP - Summary

---

OVERVIEW

Migrating AWS Identity Center from Active Directory to PingOne is a destructive operation. AWS will delete all users, groups, and permission assignments when the identity source changes. All access must be manually reconfigured.

IMPACT

All users lose AWS console access during migration. All group-to-permission-to-account mappings are deleted and must be recreated. This is a one-way migration; reverting requires repeating the same process.

WHAT IS DELETED: All users, groups, permission assignments, and active sessions.
WHAT IS PRESERVED: Permission sets (policies), AWS account connections, and IAM roles (unusable until reassigned).

---

MIGRATION PHASES

Preparation: Export all current users, groups, and assignments. Configure PingOne with SAML and SCIM. Develop automation scripts. Test in non-production environment.

Execution: Change identity source to PingOne (triggers deletion). Enable SCIM to sync users/groups. Run scripts to recreate all permission assignments. Validate critical access.

Post-Migration: Validate all user access. Troubleshoot issues. Update documentation.

---

REQUIREMENTS

PingOne: SAML 2.0 and SCIM 2.0 configured with proper attribute mapping.
AWS: SCIM endpoint enabled. Automation scripts for bulk assignment recreation.

---

KEY RISKS

High: Extended downtime if automation fails. Users unable to access critical systems. Rollback requires repeating destructive process.
Medium: Incomplete assignment recreation.

Mitigation: Test in non-production first. Develop and validate automation scripts. Schedule during low-usage period.

---

DECISION POINTS

How many users and assignments need recreation? What is the acceptable maintenance window? Which users/applications are critical? Has non-production testing been completed? Who executes the migration? What is the user communication plan?

---

NEXT STEPS

If approved: Develop automation scripts, schedule non-production test, create production runbook, coordinate maintenance window, prepare user communications.
