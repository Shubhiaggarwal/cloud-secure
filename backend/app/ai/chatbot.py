"""
ai/chatbot.py

Conversational CLI for the AI Security Assistant. Combines:
  - Gemini chat completions + manual tool/function calling
  - Real CSPM findings (ai/tools.py)
  - RAG over the security knowledge base (ai/rag.py)
  - Simple in-memory conversation history (Phase 13)

This module is only imported/used AFTER scanner.py has completed a scan and
called ai.tools.set_findings(...). It never invents AWS findings - every
finding-shaped answer traces back to a tool call against real scan data.
"""

import json

from app import config
from app.ai.prompts import SYSTEM_PROMPT
from app.ai.tools import TOOL_SCHEMAS, TOOL_FUNCTIONS
from app.ai import rag

MAX_TOOL_ITERATIONS = 5


def _search_security_knowledge(query=None, **kwargs):
    try:
        results = rag.query(query, n_results=3)
    except Exception as e:
        return {"error": f"Knowledge base unavailable: {e}"}

    if not results:
        return {"results": [], "note": "No relevant knowledge base content found."}
    return {"results": results}


# Merge the RAG tool into the same dispatch table used for CSPM tools, so
# the chatbot loop below doesn't need to special-case it.
ALL_TOOL_FUNCTIONS = {**TOOL_FUNCTIONS, "search_security_knowledge": _search_security_knowledge}


def _get_client():
    from google import genai
    return genai.Client(api_key=config.GEMINI_API_KEY)


def _build_gemini_tools():
    """Converts our provider-agnostic TOOL_SCHEMAS (ai/tools.py) into
    Gemini FunctionDeclaration/Tool objects."""
    from google.genai import types

    declarations = []
    for entry in TOOL_SCHEMAS:
        fn = entry["function"]
        declarations.append(
            types.FunctionDeclaration(
                name=fn["name"],
                description=fn["description"],
                parameters_json_schema=fn["parameters"],
            )
        )
    return [types.Tool(function_declarations=declarations)]


def _call_tool(name, args):
    """args is already a dict (Gemini parses arguments for us, unlike raw JSON)."""
    args = args or {}
    func = ALL_TOOL_FUNCTIONS.get(name)
    if func is None:
        return {"error": f"Unknown tool: {name}"}

    try:
        return func(**args)
    except Exception as e:
        return {"error": f"Tool '{name}' failed: {e}"}


def ask(client, contents):
    """
    Sends the conversation to Gemini, resolving tool calls in a loop
    (up to MAX_TOOL_ITERATIONS) until the model returns a final text answer.

    `contents` is a list of google.genai.types.Content and is mutated/
    extended in place (and also returned) so the caller can keep it as the
    running conversation history (Phase 13).
    """
    from google.genai import types

    generation_config = types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        tools=_build_gemini_tools(),
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
    )

    for _ in range(MAX_TOOL_ITERATIONS):
        try:
            response = client.models.generate_content(
                model=config.GEMINI_MODEL,
                contents=contents,
                config=generation_config,
            )
        except Exception as e:
            return f"[AI error] Couldn't reach Gemini: {e}", contents

        function_calls = response.function_calls

        if not function_calls:
            model_content = response.candidates[0].content
            contents.append(model_content)
            return response.text, contents

        # The model wants to call one or more tools - append its request,
        # then append each tool's result, then loop back.
        contents.append(response.candidates[0].content)

        response_parts = []
        for fc in function_calls:
            result = _call_tool(fc.name, fc.args)
            response_parts.append(
                types.Part.from_function_response(
                    name=fc.name,
                    response={"result": json.loads(json.dumps(result, default=str))},
                )
            )
        contents.append(types.Content(role="user", parts=response_parts))

    return "[AI] I wasn't able to finish answering that within the tool-call limit. Try rephrasing?", contents


def run_chat():
    """Starts the interactive CLI chat loop."""
    from google.genai import types

    print("=" * 60)
    print("AWS Security Assistant")
    print("=" * 60)
    print("Ask about your scan results, e.g. 'What are my critical issues?'")
    print("Type 'exit' or 'quit' to leave.\n")

    if not config.has_gemini_key():
        print("[!] GEMINI_API_KEY is not set, so the AI assistant can't run.")
        print("    Get a free key at https://aistudio.google.com/apikey, set it in")
        print("    your .env file (see .env.example), and re-run.")
        print("    The CSPM scan above still ran and printed normally.\n")
        return

    client = _get_client()
    contents = []

    if not rag.is_ready():
        print("[i] Knowledge base not ingested yet - general security knowledge answers "
              "will be limited until you run 'python ingest.py'.\n")

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting AI Security Assistant.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit"):
            print("Exiting AI Security Assistant.")
            break

        contents.append(types.Content(role="user", parts=[types.Part.from_text(text=user_input)]))

        try:
            answer, contents = ask(client, contents)
        except Exception as e:
            print(f"\nAI: [Unexpected error, please try again: {e}]\n")
            continue

        print(f"\nAI:\n{answer}\n")
