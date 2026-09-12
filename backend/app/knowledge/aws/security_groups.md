# Security Groups

## Overview
Security groups act as virtual firewalls for EC2 instances and other
resources, controlling inbound and outbound traffic at the instance/ENI
level. An inbound rule with a source CIDR of `0.0.0.0/0` allows traffic
from any IPv4 address on the internet.

## Commonly Exposed Ports
Certain ports are frequent targets for automated scanning and brute-force
attacks when left open to the world, including:
- 22 (SSH)
- 3389 (RDP)
- 3306 (MySQL)
- 5432 (PostgreSQL)
- 27017 (MongoDB)

Leaving administrative or database ports open to `0.0.0.0/0` is one of the
fastest ways an AWS resource gets compromised, often within minutes of
being provisioned, since attackers continuously scan the entire IPv4 space
for these ports.

## Remediation Steps
1. Restrict inbound rules to specific, trusted CIDR ranges (office IP, VPN
   range, bastion host) instead of `0.0.0.0/0`.
2. For administrative access (SSH/RDP), prefer a bastion host, VPN, or
   AWS Systems Manager Session Manager instead of exposing the port directly.
3. For databases, keep them in private subnets with no direct internet route,
   and only allow access from application security groups.
4. Regularly audit security groups for rules that are no longer needed.
