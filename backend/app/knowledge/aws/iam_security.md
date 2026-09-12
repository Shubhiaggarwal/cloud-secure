# IAM Security

## Multi-Factor Authentication (MFA)
IAM users authenticate with a username/password or access keys. If either
is compromised (phishing, credential stuffing, leaked in a repo, etc.) and
MFA is not enabled, an attacker can log in with no second factor required.
MFA (a virtual/hardware device or security key) adds a second, time-limited
proof of identity, dramatically reducing the value of a stolen password.
AWS recommends MFA for all IAM users, and especially for the root account
and any user with administrative permissions.

## Least Privilege and Wildcard Policies
An IAM policy statement with `"Action": "*"` and `"Resource": "*"` grants
unrestricted access to every AWS action on every resource in the account.
If the credentials for that user are ever compromised, the attacker has
full control of the AWS account - not just a limited blast radius. The
principle of least privilege means granting only the specific actions and
resources a user or role actually needs, and reviewing/narrowing broad
policies over time.

## Root Account and Access Keys
The root account should not be used for daily work and should have MFA
enabled. Long-lived IAM user access keys are more risky than temporary
credentials (via roles/STS); where possible, prefer roles for workloads and
enforce key rotation for any access keys that must exist.

## Remediation Steps
1. Enable MFA for every IAM user, prioritizing users with elevated permissions.
2. Replace wildcard (`*`/`*`) policies with scoped policies listing only the
   actions/resources actually required.
3. Use IAM Access Analyzer or policy simulator to validate scoped-down policies
   before removing the old ones.
4. Prefer roles and temporary credentials over long-lived access keys where possible.
