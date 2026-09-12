# CIS AWS Foundations Benchmark (Summary)

The Center for Internet Security (CIS) AWS Foundations Benchmark is a
widely-adopted set of prescriptive configuration recommendations for
securing an AWS account. This is a summary of the sections most relevant to
this project's CSPM checks - not the full benchmark text.

## Identity and Access Management
- Ensure MFA is enabled for all IAM users with a console password.
- Ensure IAM policies do not grant full administrative privileges via
  wildcard `Action: *` combined with `Resource: *` unless absolutely
  necessary and tightly controlled.
- Ensure access keys are rotated regularly and unused credentials are removed.

## Storage
- Ensure S3 buckets are not publicly accessible unless intentionally
  configured for public content (e.g. static website hosting).
- Ensure S3 Block Public Access is enabled at the account level.
- Ensure default encryption is enabled on S3 buckets.

## Logging and Monitoring
- Ensure CloudTrail is enabled in all regions.
- Ensure CloudTrail logs are encrypted and validated for integrity.
- Ensure a log metric filter and alarm exist for unauthorized API calls.

## Networking
- Ensure no security group allows unrestricted ingress (`0.0.0.0/0`) to
  administrative ports (22, 3389) or common database ports (3306, 5432,
  27017).
- Ensure the default security group of every VPC restricts all traffic.

## Why CIS Matters for This Project
This project's CSPM checks (S3 public access/BPA/encryption, IAM MFA/
wildcard policies, open security groups, CloudTrail status) map directly
onto CIS AWS Foundations control areas above, giving the scan results a
recognized, industry-standard frame of reference rather than an arbitrary
rule set.
