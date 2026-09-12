"""
engine/risk_engine.py

Turns a flat list of findings (as produced by checks/*.py) into aggregate
risk information: counts per severity and an overall security score.

This is intentionally simple (no ML, no external calls) - a transparent,
explainable scoring model is more useful for a CSPM MVP than a black box.
"""

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

# Points deducted from a 100-point baseline for each finding of a given
# severity. Weights are intentionally simple and easy to explain.
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
}


def summarize_findings(findings):
    """
    Returns a dict of counts per severity, plus a "TOTAL" key.

    Example:
        {"CRITICAL": 2, "HIGH": 4, "MEDIUM": 3, "LOW": 0, "TOTAL": 9}
    """
    summary = {severity: 0 for severity in SEVERITY_ORDER}

    for finding in findings:
        severity = finding.get("severity", "LOW").upper()
        if severity not in summary:
            summary[severity] = 0
        summary[severity] += 1

    summary["TOTAL"] = len(findings)
    return summary


def calculate_security_score(findings):
    """
    Calculates a simple 0-100 security score. Starts at 100 and deducts
    points per finding based on severity. Floors at 0.
    """
    score = 100
    for finding in findings:
        severity = finding.get("severity", "LOW").upper()
        score -= SEVERITY_WEIGHTS.get(severity, 1)

    return max(0, score)


def get_score_label(score):
    """Human-readable label for a numeric security score."""
    if score >= 90:
        return "Excellent"
    if score >= 75:
        return "Good"
    if score >= 50:
        return "Needs Improvement"
    return "Critical Risk"


def group_by_severity(findings):
    """Returns a dict mapping severity -> list of findings, in priority order."""
    grouped = {severity: [] for severity in SEVERITY_ORDER}
    for finding in findings:
        severity = finding.get("severity", "LOW").upper()
        grouped.setdefault(severity, []).append(finding)
    return grouped
