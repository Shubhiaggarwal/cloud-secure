# Maps each type of finding to a real MITRE ATT&CK technique.
# Reference: https://attack.mitre.org/

MITRE_MAP = {
    "mfa_missing": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts"
    },
    "wildcard_policy": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation"
    },
    "public_bucket": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage Object"
    },
    "block_public_access_disabled": {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage Object"
    },
    "encryption_missing": {
        "technique_id": "T1552",
        "technique_name": "Unsecured Credentials"  # placeholder-style tag for unencrypted data exposure
    },
    "cloudtrail_disabled": {
        "technique_id": "T1562.008",
        "technique_name": "Impair Defenses: Disable Cloud Logs"
    },
    "open_security_group": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application"
    },
}


def get_mitre_tag(finding_type):
    """
    Looks up the MITRE ATT&CK technique for a given finding type.
    Returns a formatted string, or 'N/A' if not mapped.
    """
    mapping = MITRE_MAP.get(finding_type)
    if mapping is None:
        return "N/A"
    return f"{mapping['technique_id']} - {mapping['technique_name']}"