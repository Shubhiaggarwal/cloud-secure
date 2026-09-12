from app.engine.mitre_mapping import get_mitre_tag

DANGEROUS_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
}


def check_open_security_groups(ec2_client):
    """
    Checks all security groups for inbound rules that expose
    sensitive ports to the entire internet (0.0.0.0/0).
    """
    findings = []

    response = ec2_client.describe_security_groups()
    security_groups = response["SecurityGroups"]

    for sg in security_groups:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "unknown")

        for permission in sg["IpPermissions"]:
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")

            ip_ranges = permission.get("IpRanges", [])
            is_open_to_internet = any(
                ip_range.get("CidrIp") == "0.0.0.0/0" for ip_range in ip_ranges
            )

            if not is_open_to_internet:
                continue

            if from_port is not None and to_port is not None:
                for port, service_name in DANGEROUS_PORTS.items():
                    if from_port <= port <= to_port:
                        findings.append({
                            "resource": f"Security Group: {sg_name} ({sg_id})",
                            "finding": f"Port {port} ({service_name}) is open to 0.0.0.0/0 (entire internet)",
                            "severity": "CRITICAL",
                            "impact": f"Anyone on the internet can attempt to connect to {service_name} on this instance, a common target for brute-force and exploitation attempts.",
                            "recommendation": "Restrict this rule to specific trusted IP ranges instead of 0.0.0.0/0.",
                            "mitre_attack": get_mitre_tag("open_security_group")
                        })
            else:
                findings.append({
                    "resource": f"Security Group: {sg_name} ({sg_id})",
                    "finding": "All ports are open to 0.0.0.0/0 (entire internet)",
                    "severity": "CRITICAL",
                    "impact": "Every port on this instance is reachable from any IP address on the internet.",
                    "recommendation": "Restrict this rule to specific ports and trusted IP ranges.",
                    "mitre_attack": get_mitre_tag("open_security_group")
                })

    return findings