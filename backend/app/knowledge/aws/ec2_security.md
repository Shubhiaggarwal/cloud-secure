# EC2 Security

## Attack Surface
EC2 instances are exposed to risk primarily through the network paths that
reach them (security groups, subnets/routing, and public IP assignment) and
through the software/credentials running on them (outdated packages,
hardcoded secrets, over-permissioned instance roles).

## Instance Roles vs. Long-Lived Keys
Attaching an IAM role to an EC2 instance (rather than embedding long-lived
access keys on the instance) is the recommended way to grant AWS API access
to workloads. Roles provide short-lived, automatically-rotated credentials
and avoid the risk of keys being leaked from disk, logs, or version control.

## Public IP Exposure
Instances that don't need to be reachable from the internet should not have
a public IP at all - placing them in a private subnet removes an entire
class of exposure (open ports, unpatched services) regardless of security
group configuration.

## Remediation Steps
1. Avoid attaching public IPs to instances that don't require direct
   internet access.
2. Use IAM instance roles instead of embedding access keys on instances.
3. Keep AMIs and installed packages patched; use Systems Manager Patch
   Manager for fleet-wide patching.
4. Combine with tightly-scoped security groups (see security_groups.md).
