# CSPM Remediation Guides (This Project)

Quick-reference remediation steps matching each finding type this scanner
produces. These are read-only recommendations - this project never
executes changes to the AWS account automatically.

## MFA Missing (IAM)
1. Sign in to the IAM console as the affected user (or an admin).
2. Navigate to Security credentials > Assign MFA device.
3. Register a virtual MFA app (or hardware key) and confirm two consecutive codes.
4. Re-run the scan to confirm the finding clears.

## Wildcard IAM Policy
1. Identify what the user actually needs to do (check CloudTrail history if unsure).
2. Write a scoped policy listing only those specific actions/resources.
3. Attach the scoped policy, test the user's workflow still works.
4. Remove the wildcard inline policy.

## Public S3 Bucket / Bucket Policy
1. Open the bucket's Permissions tab in the S3 console.
2. Review the bucket policy; remove any `Principal: "*"` statement unless
   the bucket is intentionally public (e.g. static site assets).
3. Enable S3 Block Public Access for the bucket (all four settings) unless
   there's a specific, reviewed reason not to.

## S3 Encryption Missing
1. Open the bucket's Properties tab > Default encryption.
2. Enable SSE-S3 (simplest) or SSE-KMS (if you need customer-managed keys).
3. Existing objects are not retroactively encrypted - consider a batch
   operation to re-encrypt existing objects if required for compliance.

## Open Security Group (Dangerous Port to 0.0.0.0/0)
1. Open the EC2 console > Security Groups > the affected group.
2. Edit the inbound rule; replace `0.0.0.0/0` with a specific trusted CIDR
   (office/VPN range), or remove the rule if not needed.
3. For administrative access, consider Session Manager or a bastion host instead.

## CloudTrail Disabled / Not Logging
1. Open the CloudTrail console > Trails.
2. Create a trail (or resume an existing one) covering all regions, logging
   to a dedicated S3 bucket.
3. Confirm `IsLogging` is true after saving.
