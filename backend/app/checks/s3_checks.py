import json
from app.engine.mitre_mapping import get_mitre_tag


def check_public_buckets(s3_client):
    """
    Checks all S3 buckets for a bucket policy that grants public access
    (Principal: "*" combined with Effect: "Allow").
    """
    findings = []

    buckets_response = s3_client.list_buckets()
    buckets = buckets_response["Buckets"]

    for bucket in buckets:
        bucket_name = bucket["Name"]

        try:
            policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_document = json.loads(policy_response["Policy"])
        except s3_client.exceptions.ClientError:
            continue

        statements = policy_document["Statement"]
        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            principal = statement.get("Principal")
            effect = statement.get("Effect")

            is_public_principal = (principal == "*") or (
                isinstance(principal, dict) and principal.get("AWS") == "*"
            )

            if effect == "Allow" and is_public_principal:
                findings.append({
                    "resource": f"S3 Bucket: {bucket_name}",
                    "finding": "Bucket policy allows public access (Principal: *)",
                    "severity": "CRITICAL",
                    "impact": "Anyone on the internet may be able to access objects in this bucket, depending on the actions allowed.",
                    "recommendation": "Review the bucket policy and remove public access unless explicitly required. Enable S3 Block Public Access.",
                    "mitre_attack": get_mitre_tag("public_bucket")
                })

    return findings


def check_block_public_access(s3_client):
    """
    Checks whether S3 Block Public Access is properly configured for each bucket.
    """
    findings = []

    buckets_response = s3_client.list_buckets()
    buckets = buckets_response["Buckets"]

    for bucket in buckets:
        bucket_name = bucket["Name"]

        try:
            bpa_response = s3_client.get_public_access_block(Bucket=bucket_name)
            config = bpa_response["PublicAccessBlockConfiguration"]
        except s3_client.exceptions.ClientError:
            findings.append({
                "resource": f"S3 Bucket: {bucket_name}",
                "finding": "No Block Public Access configuration found",
                "severity": "HIGH",
                "impact": "This bucket has no safety net against accidental public exposure via policy or ACL misconfiguration.",
                "recommendation": "Enable S3 Block Public Access for this bucket.",
                "mitre_attack": get_mitre_tag("block_public_access_disabled")
            })
            continue

        all_enabled = (
            config.get("BlockPublicAcls", False)
            and config.get("IgnorePublicAcls", False)
            and config.get("BlockPublicPolicy", False)
            and config.get("RestrictPublicBuckets", False)
        )

        if not all_enabled:
            findings.append({
                "resource": f"S3 Bucket: {bucket_name}",
                "finding": "Block Public Access is not fully enabled",
                "severity": "MEDIUM",
                "impact": "One or more public access protections are disabled, increasing the risk of accidental exposure.",
                "recommendation": "Enable all four Block Public Access settings for this bucket.",
                "mitre_attack": get_mitre_tag("block_public_access_disabled")
            })

    return findings


def check_bucket_encryption(s3_client):
    """
    Checks whether each S3 bucket has server-side encryption enabled.
    """
    findings = []

    buckets_response = s3_client.list_buckets()
    buckets = buckets_response["Buckets"]

    for bucket in buckets:
        bucket_name = bucket["Name"]

        try:
            s3_client.get_bucket_encryption(Bucket=bucket_name)
        except s3_client.exceptions.ClientError:
            findings.append({
                "resource": f"S3 Bucket: {bucket_name}",
                "finding": "Server-side encryption is not enabled",
                "severity": "MEDIUM",
                "impact": "Data stored in this bucket is not encrypted at rest, which could expose it if underlying storage is ever accessed without authorization.",
                "recommendation": "Enable default server-side encryption (SSE-S3 or SSE-KMS) for this bucket.",
                "mitre_attack": get_mitre_tag("encryption_missing")
            })

    return findings