# CSPM Scanner Rules (This Project)

This document describes the specific checks implemented by this scanner's
`checks/` modules, so the AI assistant can explain *why* a rule exists in
this specific tool, not just AWS best practice in the abstract.

## IAM Rules
- **check_mfa_for_users**: Flags (severity HIGH) any IAM user with zero MFA
  devices registered.
- **check_wildcard_policies**: Flags (severity CRITICAL) any inline IAM
  user policy statement with `Action: "*"` AND `Resource: "*"` combined
  with `Effect: "Allow"`.

## S3 Rules
- **check_public_buckets**: Flags (severity CRITICAL) any bucket policy
  statement with `Effect: "Allow"` and a `Principal` of `"*"` (or
  `{"AWS": "*"}`).
- **check_block_public_access**: Flags (severity HIGH) buckets with no
  Block Public Access configuration at all, and (severity MEDIUM) buckets
  where BPA exists but not all four protections are enabled.
- **check_bucket_encryption**: Flags (severity MEDIUM) buckets with no
  server-side encryption configuration.

## EC2 / Security Group Rules
- **check_open_security_groups**: Flags (severity CRITICAL) any security
  group rule allowing inbound traffic from `0.0.0.0/0` to a dangerous port
  (22 SSH, 3389 RDP, 3306 MySQL, 5432 PostgreSQL, 27017 MongoDB), or any
  rule that opens all ports to `0.0.0.0/0`.

## CloudTrail Rules
- **check_cloudtrail_enabled**: Flags (severity HIGH) an account with no
  CloudTrail trail configured at all, or a trail that exists but has
  logging turned off.

## Severity Scale
CRITICAL > HIGH > MEDIUM > LOW. The security score (0-100) deducts 10
points per CRITICAL finding, 5 per HIGH, 2 per MEDIUM, and 1 per LOW,
floored at 0.
