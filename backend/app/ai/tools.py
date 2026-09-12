"""
ai/tools.py

The controlled interface between the AI Security Assistant and real CSPM
data. These are the functions exposed to the LLM as "tools" (function
calling). The LLM can only ever see findings that actually came out of the
scanner - it has no way to invent or fabricate a finding.

Findings are populated once per run by scanner.py (via set_findings), right
after a scan completes. This is intentionally simple in-memory storage
(a module-level list) - appropriate for a single CLI session MVP. See
README / PHASE 6 notes for how this would be swapped for PostgreSQL later
without changing the tool function signatures.
"""

from app.engine.risk_engine import (
    summarize_findings,
    calculate_security_score,
    get_score_label,
    group_by_severity,
)

_findings = []


def set_findings(findings):
    """Called once by scanner.py after a scan completes."""
    global _findings
    _findings = findings


def get_all_findings():
    """Returns every finding from the most recent scan."""
    return list(_findings)


def get_critical_findings():
    """Returns only CRITICAL severity findings."""
    return [f for f in _findings if f.get("severity", "").upper() == "CRITICAL"]


def get_findings_by_severity(severity):
    """Returns findings matching the given severity (case-insensitive)."""
    severity = (severity or "").upper()
    return [f for f in _findings if f.get("severity", "").upper() == severity]


def get_findings_by_resource(resource_id):
    """
    Returns findings whose 'resource' field contains the given resource
    identifier (case-insensitive substring match, since resource strings
    include names like 'S3 Bucket: company-data').
    """
    needle = (resource_id or "").lower()
    return [f for f in _findings if needle in f.get("resource", "").lower()]


def get_security_summary():
    """Returns counts of findings per severity plus the total."""
    return summarize_findings(_findings)


def get_security_score():
    """Returns the overall 0-100 security score and its label."""
    score = calculate_security_score(_findings)
    return {"score": score, "label": get_score_label(score)}


def get_remediation_plan():
    """
    Returns findings grouped by severity (Critical first), for building a
    prioritized remediation plan. Each group only contains real findings.
    """
    return group_by_severity(_findings)


# ---------------------------------------------------------------------------
# Tool schema (provider-agnostic JSON-schema shape; converted to Gemini's
# FunctionDeclaration format in ai/chatbot.py)
# ---------------------------------------------------------------------------
# One entry per Python function above. Kept in sync manually since there are
# only a handful of tools - not worth a decorator/registry abstraction for
# an MVP of this size.

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "get_all_findings",
            "description": "Get every security finding from the most recent CSPM scan.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_critical_findings",
            "description": "Get only the CRITICAL severity findings from the most recent CSPM scan.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_findings_by_severity",
            "description": "Get findings filtered by severity level.",
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        "description": "Severity level to filter by.",
                    }
                },
                "required": ["severity"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_findings_by_resource",
            "description": "Get findings related to a specific AWS resource, e.g. a bucket name, IAM user name, or security group id.",
            "parameters": {
                "type": "object",
                "properties": {
                    "resource_id": {
                        "type": "string",
                        "description": "Resource name or id to search for, e.g. 'company-data' or 'admin-user'.",
                    }
                },
                "required": ["resource_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_security_summary",
            "description": "Get counts of findings per severity level (Critical, High, Medium, Low) and the total.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_security_score",
            "description": "Get the overall AWS account security score (0-100) and a human-readable label.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_remediation_plan",
            "description": "Get all findings grouped by severity (Critical first, then High, Medium, Low), for building a prioritized remediation plan.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_security_knowledge",
            "description": (
                "Search the cybersecurity knowledge base (AWS documentation, CIS AWS "
                "Foundations Benchmark, and CSPM remediation guidance) for general "
                "security best practices and explanations. Use this for 'why is this "
                "risky' or 'how do I fix this' style questions, as opposed to questions "
                "about the specific AWS account, which should use the CSPM finding tools."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "A natural-language security question or topic, e.g. 'risks of public S3 buckets'.",
                    }
                },
                "required": ["query"],
            },
        },
    },
]


# Maps tool name -> the callable the chatbot should invoke.
TOOL_FUNCTIONS = {
    "get_all_findings": lambda **kwargs: get_all_findings(),
    "get_critical_findings": lambda **kwargs: get_critical_findings(),
    "get_findings_by_severity": lambda severity=None, **kwargs: get_findings_by_severity(severity),
    "get_findings_by_resource": lambda resource_id=None, **kwargs: get_findings_by_resource(resource_id),
    "get_security_summary": lambda **kwargs: get_security_summary(),
    "get_security_score": lambda **kwargs: get_security_score(),
    "get_remediation_plan": lambda **kwargs: get_remediation_plan(),
}
