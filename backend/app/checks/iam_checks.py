from app.engine.mitre_mapping import get_mitre_tag


def check_mfa_for_users(iam_client):
    """
    Checks all IAM users in the account for MFA devices.
    Returns a list of findings (dicts) for users WITHOUT MFA.
    """
    findings = []

    users_response = iam_client.list_users()
    users = users_response["Users"]

    for user in users:
        username = user["UserName"]
        mfa_response = iam_client.list_mfa_devices(UserName=username)
        mfa_devices = mfa_response["MFADevices"]

        if len(mfa_devices) == 0:
            findings.append({
                "resource": f"IAM User: {username}",
                "finding": "MFA is not enabled for this user",
                "severity": "HIGH",
                "impact": "If this user's password is compromised, an attacker can log in with no second factor required.",
                "recommendation": "Enable MFA (Multi-Factor Authentication) for this user in the IAM console.",
                "mitre_attack": get_mitre_tag("mfa_missing")
            })

    return findings


def check_wildcard_policies(iam_client):
    """
    Checks all IAM users' inline policies for dangerous wildcard permissions:
    Action: "*" combined with Resource: "*"
    Returns a list of findings.
    """
    findings = []

    users_response = iam_client.list_users()
    users = users_response["Users"]

    for user in users:
        username = user["UserName"]

        policy_names_response = iam_client.list_user_policies(UserName=username)
        policy_names = policy_names_response["PolicyNames"]

        for policy_name in policy_names:
            policy_response = iam_client.get_user_policy(
                UserName=username,
                PolicyName=policy_name
            )
            policy_document = policy_response["PolicyDocument"]

            statements = policy_document["Statement"]
            if isinstance(statements, dict):
                statements = [statements]

            for statement in statements:
                action = statement.get("Action")
                resource = statement.get("Resource")

                is_wildcard_action = (action == "*") or (isinstance(action, list) and "*" in action)
                is_wildcard_resource = (resource == "*") or (isinstance(resource, list) and "*" in resource)

                if is_wildcard_action and is_wildcard_resource:
                    findings.append({
                        "resource": f"IAM User: {username}, Policy: {policy_name}",
                        "finding": "Policy grants wildcard Action (*) and wildcard Resource (*)",
                        "severity": "CRITICAL",
                        "impact": "This user can perform any action on any resource in the AWS account - a compromised credential means full account compromise.",
                        "recommendation": "Scope this policy down to only the specific actions and resources this user actually needs (principle of least privilege).",
                        "mitre_attack": get_mitre_tag("wildcard_policy")
                    })

    return findings