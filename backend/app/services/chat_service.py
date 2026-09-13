"""
app/services/chat_service.py

The always-available AI Security Assistant, adapted from the original CLI's
ai/chatbot.py + ai/tools.py for a multi-tenant web backend:

  - Findings are scoped to ONE scan (passed in per-request), never a global
    module-level list - critical so Company A's findings can never leak
    into Company B's chat session.
  - Conversation history is kept server-side, keyed by session_id, so the
    chat panel in the UI can have a running conversation across turns.
  - Same Gemini tool-calling + RAG pattern as the CLI tool otherwise.

NOTE: in-memory session storage (a dict) is fine for a single-process dev
server. For real production with multiple backend workers, swap
`_SESSIONS` for Redis (session_id -> serialized history) - the interface
below (`get_reply`) wouldn't need to change.
"""

import json
import threading

from app import config
from app.ai.prompts import SYSTEM_PROMPT
from app.ai import rag
from app.engine.risk_engine import (
    summarize_findings, calculate_security_score, get_score_label, group_by_severity,
)

MAX_TOOL_ITERATIONS = 5

# session_id -> list[types.Content]  (simple in-memory store; see note above)
_SESSIONS = {}
_LOCK = threading.Lock()


def _tools_for_findings(findings: list):
    """Builds the same tool-function dispatch table as the CLI, but bound
    to THIS request's findings via closures instead of a global list."""

    def get_all_findings(**_):
        return list(findings)

    def get_critical_findings(**_):
        return [f for f in findings if f.get("severity", "").upper() == "CRITICAL"]

    def get_findings_by_severity(severity=None, **_):
        severity = (severity or "").upper()
        return [f for f in findings if f.get("severity", "").upper() == severity]

    def get_findings_by_resource(resource_id=None, **_):
        needle = (resource_id or "").lower()
        return [f for f in findings if needle in f.get("resource", "").lower()]

    def get_security_summary(**_):
        return summarize_findings(findings)

    def get_security_score(**_):
        score = calculate_security_score(findings)
        return {"score": score, "label": get_score_label(score)}

    def get_remediation_plan(**_):
        return group_by_severity(findings)

    def search_security_knowledge(query=None, **_):
        try:
            results = rag.query(query, n_results=3)
        except Exception as e:
            return {"error": f"Knowledge base unavailable: {e}"}
        if not results:
            return {"results": [], "note": "No relevant knowledge base content found."}
        return {"results": results}

    return {
        "get_all_findings": get_all_findings,
        "get_critical_findings": get_critical_findings,
        "get_findings_by_severity": get_findings_by_severity,
        "get_findings_by_resource": get_findings_by_resource,
        "get_security_summary": get_security_summary,
        "get_security_score": get_security_score,
        "get_remediation_plan": get_remediation_plan,
        "search_security_knowledge": search_security_knowledge,
    }


TOOL_SCHEMAS = [
    {"name": "get_all_findings", "description": "Get every security finding from this scan.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "get_critical_findings", "description": "Get only CRITICAL severity findings from this scan.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "get_findings_by_severity", "description": "Get findings filtered by severity level.",
     "parameters": {"type": "object", "properties": {
         "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                      "description": "Severity level to filter by."}},
         "required": ["severity"]}},
    {"name": "get_findings_by_resource", "description": "Get findings related to a specific AWS resource.",
     "parameters": {"type": "object", "properties": {
         "resource_id": {"type": "string", "description": "Resource name or id, e.g. 'company-data'."}},
         "required": ["resource_id"]}},
    {"name": "get_security_summary", "description": "Get counts of findings per severity level and the total.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "get_security_score", "description": "Get the overall 0-100 security score and a label.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "get_remediation_plan", "description": "Get all findings grouped by severity, for prioritized remediation.",
     "parameters": {"type": "object", "properties": {}}},
    {"name": "search_security_knowledge",
     "description": ("Search the cybersecurity knowledge base (AWS docs, CIS AWS Foundations "
                      "Benchmark, CSPM remediation guidance) for general best practices. Use "
                      "this for 'why is this risky' / 'how do I fix this' style questions."),
     "parameters": {"type": "object", "properties": {
         "query": {"type": "string", "description": "A natural-language security question or topic."}},
         "required": ["query"]}},
]


def _get_client():
    from google import genai
    return genai.Client(api_key=config.GEMINI_API_KEY)


def _build_gemini_tools():
    from google.genai import types
    declarations = [
        types.FunctionDeclaration(
            name=t["name"], description=t["description"], parameters_json_schema=t["parameters"],
        )
        for t in TOOL_SCHEMAS
    ]
    return [types.Tool(function_declarations=declarations)]


def get_reply(session_id: str, user_message: str, findings: list, tool_call_log: list = None) -> str:
    """
    Sends `user_message` to Gemini with tool-calling enabled, resolving any
    tool calls against THIS scan's findings, and returns the final text
    reply. Conversation history persists across calls with the same
    session_id.
    """
    from google.genai import types

    if not config.has_gemini_key():
        return ("The AI assistant isn't configured yet - ask your admin to set "
                "GEMINI_API_KEY on the backend.")

    tool_functions = _tools_for_findings(findings)
    client = _get_client()

    with _LOCK:
        contents = _SESSIONS.setdefault(session_id, [])
        contents.append(types.Content(role="user", parts=[types.Part.from_text(text=user_message)]))

    generation_config = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        tools=_build_gemini_tools(),
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
    )

    for _ in range(MAX_TOOL_ITERATIONS):
        try:
            response = client.models.generate_content(
                model=config.GEMINI_MODEL, contents=contents, config=generation_config,
            )
        except Exception as e:
            return f"[AI error] Couldn't reach Gemini: {e}"

        function_calls = response.function_calls
        if not function_calls:
            contents.append(response.candidates[0].content)
            with _LOCK:
                _SESSIONS[session_id] = contents
            return response.text

        contents.append(response.candidates[0].content)
        if tool_call_log is not None:
            tool_call_log.extend(fc.name for fc in function_calls)
        response_parts = []
        for fc in function_calls:
            func = tool_functions.get(fc.name)
            args = fc.args or {}
            try:
                result = func(**args) if func else {"error": f"Unknown tool: {fc.name}"}
            except Exception as e:
                result = {"error": f"Tool '{fc.name}' failed: {e}"}
            response_parts.append(
                types.Part.from_function_response(
                    name=fc.name,
                    response={"result": json.loads(json.dumps(result, default=str))},
                )
            )
        contents.append(types.Content(role="user", parts=response_parts))

    with _LOCK:
        _SESSIONS[session_id] = contents
    return "I wasn't able to finish answering that within the tool-call limit. Try rephrasing?"


def clear_session(session_id: str):
    with _LOCK:
        _SESSIONS.pop(session_id, None)
