# S3 Security

## Public Access Risks
Amazon S3 buckets are private by default, but misconfigured bucket policies
or ACLs can expose objects to the entire internet. A bucket policy with
`"Principal": "*"` and `"Effect": "Allow"` grants access to anyone, not just
your AWS account. This is one of the most common causes of cloud data
breaches: sensitive files, backups, logs, or database dumps left in a
public bucket can be discovered and downloaded by anyone who finds the
bucket name or URL.

## S3 Block Public Access
S3 Block Public Access (BPA) is an account- or bucket-level safety net with
four settings: `BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`,
and `RestrictPublicBuckets`. Enabling all four prevents public access even
if a policy or ACL is later misconfigured. AWS recommends enabling BPA at
the account level unless you have a specific, well-understood reason for a
bucket to be public (e.g. static website hosting).

## Encryption at Rest
S3 supports server-side encryption (SSE-S3, SSE-KMS, or SSE-C). Without
default encryption enabled, objects are stored unencrypted, which can be a
compliance issue (PCI-DSS, HIPAA, etc.) and increases exposure if the
underlying storage is ever accessed without authorization. Enabling default
bucket encryption ensures every new object is encrypted automatically,
without relying on every application/user to set encryption headers.

## Remediation Steps
1. Enable S3 Block Public Access at the account level, then per-bucket if needed.
2. Review bucket policies and ACLs; remove any `Principal: *` grants that
   aren't intentional.
3. Enable default server-side encryption (SSE-S3 is the simplest starting point).
4. Enable S3 access logging or CloudTrail data events for sensitive buckets.
5. Re-scan after making changes to confirm the finding clears.
