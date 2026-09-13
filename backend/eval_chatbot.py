"""
eval_chatbot.py

A small evaluation harness for the AI Security Assistant. Runs a fixed set
of test questions against a fixed set of sample findings, and checks two
things per question:

  1. Tool selection - did the model call the tool(s) we'd expect for that
     kind of question? (e.g. "what are my critical issues" -> should call
     get_critical_findings, not just get_all_findings)
  2. Answer grounding - does the final text answer actually mention the
     specific facts we'd expect from the sample data, rather than a vague
     generic answer?

This is intentionally simple (substring checks, not semantic similarity) -
good enough to catch regressions and give you a concrete pass/fail number,
without needing a second LLM call to judge answers.

Run from the backend/ directory:
    python eval_chatbot.py
"""

import sys
import uuid
import time 
from app.services.chat_service import get_reply

# A fixed, hand-crafted set of findings - same shape as real scan output,
# but constant across runs so eval results are comparable over time.
SAMPLE_FINDINGS = [
    {
        "service": "IAM", "rule_id": "IAM-001", "severity": "CRITICAL",
        "resource": "admin-user",
        "issue": "Policy grants wildcard Action (*) and wildcard Resource (*)",
        "impact": "This user can perform any action on any resource in the AWS account.",
        "recommendation": "Scope this policy down to only the specific actions and resources needed.",
        "mitre": "T1098 - Account Manipulation",
    },
    {
        "service": "IAM", "rule_id": "IAM-002", "severity": "HIGH",
        "resource": "admin-user",
        "issue": "MFA is not enabled for this user",
        "impact": "If this user's password is compromised, no second factor is required.",
        "recommendation": "Enable MFA for this user in the IAM console.",
        "mitre": "T1078 - Valid Accounts",
    },
    {
        "service": "S3", "rule_id": "S3-001", "severity": "CRITICAL",
        "resource": "company-data",
        "issue": "Bucket policy allows public access (Principal: *)",
        "impact": "Anyone on the internet may be able to access objects in this bucket.",
        "recommendation": "Remove public access and enable S3 Block Public Access.",
        "mitre": "T1530 - Data from Cloud Storage Object",
    },
    {
        "service": "EC2", "rule_id": "EC2-001", "severity": "CRITICAL",
        "resource": "web-sg (sg-12345)",
        "issue": "Port 22 (SSH) is open to 0.0.0.0/0",
        "impact": "Anyone on the internet can attempt to connect to SSH on this instance.",
        "recommendation": "Restrict this rule to specific trusted IP ranges.",
        "mitre": "T1190 - Exploit Public-Facing Application",
    },
    {
        "service": "CloudTrail", "rule_id": "CT-001", "severity": "HIGH",
        "resource": "AWS Account",
        "issue": "No CloudTrail trail is configured",
        "impact": "There is no audit record of API activity in this account.",
        "recommendation": "Create a CloudTrail trail that logs to an S3 bucket, covering all regions.",
        "mitre": "T1562.008 - Impair Defenses: Disable Cloud Logs",
    },
]

# Each test case: a question, which tool(s) we'd consider a correct call,
# and substrings we expect somewhere in the final answer if it's properly
# grounded in the sample findings above (case-insensitive).
TEST_CASES = [
    {
        "question": "What are my critical findings?",
        "expected_tools": {"get_critical_findings"},
        "expected_in_answer": ["admin-user", "company-data", "web-sg"],
    },
    {
        "question": "What's my overall security score?",
        "expected_tools": {"get_security_score"},
        "expected_in_answer": [],
    },
    {
        "question": "Tell me about the SSH security group issue.",
        "expected_tools": {"get_findings_by_resource", "get_all_findings", "get_findings_by_severity"},
        "expected_in_answer": ["22", "0.0.0.0/0"],
    },
    {
        "question": "Give me a summary of findings by severity.",
        "expected_tools": {"get_security_summary"},
        "expected_in_answer": [],
    },
    {
        "question": "How do I fix an S3 bucket that's publicly accessible?",
        "expected_tools": {"search_security_knowledge", "get_findings_by_resource", "get_all_findings"},
        "expected_in_answer": ["public", "block"],
    },
    {
        "question": "What should I prioritize fixing first?",
        "expected_tools": {"get_remediation_plan", "get_critical_findings", "get_security_summary"},
        "expected_in_answer": [],
    },
    {
        "question": "Is MFA enabled for admin-user?",
        "expected_tools": {"get_findings_by_resource", "get_all_findings"},
        "expected_in_answer": ["mfa"],
    },
    {
        "question": "Do I have CloudTrail logging set up?",
        "expected_tools": {"get_findings_by_resource", "get_all_findings", "get_findings_by_severity"},
        "expected_in_answer": ["cloudtrail"],
    },
]


def run_eval():
    total = len(TEST_CASES)
    tool_correct = 0
    grounding_correct = 0
    results = []

    for case in TEST_CASES:
        session_id = f"eval-{uuid.uuid4().hex[:8]}"
        tool_call_log = []

        answer = get_reply(
            session_id=session_id,
            user_message=case["question"],
            findings=SAMPLE_FINDINGS,
            tool_call_log=tool_call_log,
        )
        time.sleep(3)  # avoid hitting rate limits if running many evals in a row

        called = set(tool_call_log)
        tool_ok = bool(called & case["expected_tools"]) if case["expected_tools"] else True

        answer_lower = (answer or "").lower()
        expected_terms = case["expected_in_answer"]
        grounding_ok = all(term.lower() in answer_lower for term in expected_terms)

        if tool_ok:
            tool_correct += 1
        if grounding_ok:
            grounding_correct += 1

        results.append({
            "question": case["question"],
            "expected_tools": case["expected_tools"],
            "called_tools": called,
            "tool_ok": tool_ok,
            "expected_terms": expected_terms,
            "grounding_ok": grounding_ok,
            "answer": answer,
        })
        
    print("=" * 70)
    print("AI SECURITY ASSISTANT - EVAL REPORT")
    print("=" * 70)
    for r in results:
        status = "PASS" if (r["tool_ok"] and r["grounding_ok"]) else "FAIL"
        print(f"\n[{status}] {r['question']}")
        print(f"  Expected tools: {r['expected_tools'] or '(any)'}")
        print(f"  Called tools:   {r['called_tools'] or '(none)'}")
        print(f"  Tool selection: {'OK' if r['tool_ok'] else 'WRONG TOOL'}")
        if r["expected_terms"]:
            print(f"  Expected terms in answer: {r['expected_terms']}")
            print(f"  Grounding: {'OK' if r['grounding_ok'] else 'MISSING EXPECTED CONTENT'}")
        print(f"  Answer: {r['answer'][:200]}{'...' if len(r['answer'] or '') > 200 else ''}")

    print("\n" + "=" * 70)
    print(f"Tool selection accuracy: {tool_correct}/{total} ({tool_correct/total*100:.0f}%)")
    print(f"Answer grounding accuracy: {grounding_correct}/{total} ({grounding_correct/total*100:.0f}%)")
    print("=" * 70)


if __name__ == "__main__":
    run_eval()