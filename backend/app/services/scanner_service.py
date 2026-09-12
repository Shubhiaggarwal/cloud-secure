"""
app/services/scanner_service.py

Runs the CSPM checks (reused verbatim from the original CLI tool) against
either:
  - a real customer AWS account, via sts:AssumeRole using the role_arn /
    external_id the company configured on their AWSAccount record, or
  - a seeded moto mock account, if demo_mode is enabled on that account.

This is the one place cross-account access happens. The backend AWS
credentials used here only need `sts:AssumeRole` permission - nothing else -
because every actual read call (iam:List*, s3:Get*, etc.) happens using the
*assumed* short-lived credentials in the customer's own account.
"""

import json
import uuid

import boto3
from moto import mock_aws

from app.checks.iam_checks import check_mfa_for_users, check_wildcard_policies
from app.checks.s3_checks import (
    check_public_buckets,
    check_block_public_access,
    check_bucket_encryption,
)
from app.checks.security_group_checks import check_open_security_groups
from app.checks.cloudtrail_checks import check_cloudtrail_enabled


class ScanError(Exception):
    pass


def _assume_role_clients(role_arn: str, external_id: str, region: str):
    """
    Assumes the customer's IAM role and returns boto3 clients built from the
    temporary credentials. Never touches or stores long-lived customer keys.
    """
    sts = boto3.client("sts")
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"cspm-scan-{uuid.uuid4().hex[:8]}",
            ExternalId=external_id or None,
            DurationSeconds=3600,
        )
    except Exception as e:
        raise ScanError(f"Failed to assume role {role_arn}: {e}")

    creds = resp["Credentials"]
    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
    return {
        "iam": session.client("iam"),
        "s3": session.client("s3"),
        "ec2": session.client("ec2"),
        "cloudtrail": session.client("cloudtrail"),
    }


def _seed_demo_account(region: str, seed: int):
    """
    Builds a seeded mock AWS account with a randomized (but reproducible,
    thanks to `seed`) mix of secure and insecure resources. Using `seed`
    means the SAME demo account always gets the SAME findings on repeat
    scans (so results feel stable, not random noise), while DIFFERENT
    demo accounts get genuinely different findings from each other -
    closer to how real, distinct AWS accounts would actually differ.
    """
    import random
    rng = random.Random(seed)

    iam = boto3.client("iam", region_name=region)
    s3 = boto3.client("s3", region_name=region)
    ec2 = boto3.client("ec2", region_name=region)
    cloudtrail = boto3.client("cloudtrail", region_name=region)

    # --- IAM: 2-4 users, each randomly missing MFA and/or over-privileged ---
    user_pool = ["jane-doe", "admin-user", "dev-bot", "contractor-01", "svc-deploy", "alice"]
    rng.shuffle(user_pool)
    users = user_pool[: rng.randint(2, 4)]

    for username in users:
        iam.create_user(UserName=username)

        has_mfa = rng.random() > 0.5
        if has_mfa:
            device = iam.create_virtual_mfa_device(VirtualMFADeviceName=f"{username}-mfa")
            serial = device["VirtualMFADevice"]["SerialNumber"]
            iam.enable_mfa_device(
                UserName=username, SerialNumber=serial,
                AuthenticationCode1="123456", AuthenticationCode2="123456",
            )

        is_overprivileged = rng.random() > 0.6
        if is_overprivileged:
            iam.put_user_policy(
                UserName=username,
                PolicyName=f"{username}-full-access",
                PolicyDocument=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                }),
            )

    # --- S3: 1-3 buckets, each randomly public/unencrypted or locked down ---
    bucket_pool = ["company-data", "backups-prod", "user-uploads", "analytics-raw", "static-assets"]
    rng.shuffle(bucket_pool)
    buckets = bucket_pool[: rng.randint(1, 3)]

    for bucket in buckets:
        s3.create_bucket(Bucket=bucket)

        is_public = rng.random() > 0.5
        if is_public:
            s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow", "Principal": "*",
                    "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*",
                }],
            }))
        else:
            s3.put_public_access_block(
                Bucket=bucket,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True, "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
                },
            )

        is_encrypted = rng.random() > 0.5
        if is_encrypted:
            s3.put_bucket_encryption(
                Bucket=bucket,
                ServerSideEncryptionConfiguration={
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                },
            )

    # --- EC2: 1-2 security groups, each randomly with a risky open port ---
    sg_specs = [("web-sg", 22), ("db-sg", 3389), ("app-sg", 5432)]
    rng.shuffle(sg_specs)
    for name, port in sg_specs[: rng.randint(1, 2)]:
        sg = ec2.create_security_group(GroupName=name, Description=f"{name} demo group")
        if rng.random() > 0.4:
            ec2.authorize_security_group_ingress(
                GroupId=sg["GroupId"],
                IpPermissions=[{
                    "IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }],
            )

    # --- CloudTrail: sometimes configured, sometimes not ---
    if rng.random() > 0.5:
        bucket = "cloudtrail-logs-demo"
        s3.create_bucket(Bucket=bucket)
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/*",
            }],
        }))
        cloudtrail.create_trail(Name="main-trail", S3BucketName=bucket, IsMultiRegionTrail=True)
        cloudtrail.start_logging(Name="main-trail")
    # else: intentionally left unconfigured -> HIGH finding

    return {"iam": iam, "s3": s3, "ec2": ec2, "cloudtrail": cloudtrail}


def _normalize(f: dict) -> dict:
    """The original CLI checks return finding text under 'finding' and MITRE
    info under 'mitre_attack'. Our API/DB schema uses 'issue' and 'mitre'.
    Normalize here in one place rather than touching every check file."""
    f["issue"] = f.get("issue") or f.get("finding")
    f["mitre"] = f.get("mitre") or f.get("mitre_attack")
    return f


def _run_checks(clients) -> list:
    findings = []

    iam_findings = check_mfa_for_users(clients["iam"]) + check_wildcard_policies(clients["iam"])
    for i, f in enumerate(iam_findings, start=1):
        f.setdefault("service", "IAM")
        f.setdefault("rule_id", f"IAM-{i:03d}")
    findings += iam_findings

    s3_findings = (
        check_public_buckets(clients["s3"])
        + check_block_public_access(clients["s3"])
        + check_bucket_encryption(clients["s3"])
    )
    for i, f in enumerate(s3_findings, start=1):
        f.setdefault("service", "S3")
        f.setdefault("rule_id", f"S3-{i:03d}")
    findings += s3_findings

    sg_findings = check_open_security_groups(clients["ec2"])
    for i, f in enumerate(sg_findings, start=1):
        f.setdefault("service", "EC2")
        f.setdefault("rule_id", f"EC2-{i:03d}")
    findings += sg_findings

    ct_findings = check_cloudtrail_enabled(clients["cloudtrail"])
    for i, f in enumerate(ct_findings, start=1):
        f.setdefault("service", "CloudTrail")
        f.setdefault("rule_id", f"CT-{i:03d}")
    findings += ct_findings

    return [_normalize(f) for f in findings]


def run_scan_for_account(aws_account) -> list:
    """
    aws_account: an app.models.AWSAccount row.
    Returns a list of finding dicts (same shape the original CLI produced).
    Raises ScanError on failure (caller marks the Scan row as FAILED).
    """
    region = aws_account.region or "us-east-1"

    if aws_account.demo_mode == "true":
        with mock_aws():
            clients = _seed_demo_account(region, seed=aws_account.id)
            return _run_checks(clients)

    if not aws_account.role_arn:
        raise ScanError("No role_arn configured for this AWS account and demo_mode is off.")

    clients = _assume_role_clients(aws_account.role_arn, aws_account.external_id, region)
    return _run_checks(clients)