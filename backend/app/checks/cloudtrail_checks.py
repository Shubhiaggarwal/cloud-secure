from app.engine.mitre_mapping import get_mitre_tag


def check_cloudtrail_enabled(cloudtrail_client):
    """
    Checks whether at least one CloudTrail trail exists and is actively logging.
    """
    findings = []

    trails_response = cloudtrail_client.describe_trails()
    trails = trails_response["trailList"]

    if len(trails) == 0:
        findings.append({
            "resource": "AWS Account",
            "finding": "No CloudTrail trail is configured",
            "severity": "HIGH",
            "impact": "There is no audit record of API activity in this account. If a security incident occurs, there's no way to investigate what happened.",
            "recommendation": "Create a CloudTrail trail that logs to an S3 bucket, covering all regions.",
            "mitre_attack": get_mitre_tag("cloudtrail_disabled")
        })
        return findings

    for trail in trails:
        trail_name = trail["Name"]
        status_response = cloudtrail_client.get_trail_status(Name=trail_name)
        is_logging = status_response["IsLogging"]

        if not is_logging:
            findings.append({
                "resource": f"CloudTrail: {trail_name}",
                "finding": "Trail exists but logging is turned off",
                "severity": "HIGH",
                "impact": "This trail is configured but not actively recording API activity, creating a false sense of security.",
                "recommendation": "Enable logging for this trail.",
                "mitre_attack": get_mitre_tag("cloudtrail_disabled")
            })

    return findings