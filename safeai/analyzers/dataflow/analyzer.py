"""Data-flow analyzer — heuristic detection of untrusted input propagation.

Tracks how untrusted input (user_input, request, input, response) flows
through code into sensitive sinks (prompts, tool arguments, shell commands,
file operations). Uses line-level proxy heuristics for propagation tracking.

This is a heuristic analysis — not a full interprocedural data-flow solver.
It provides a best-effort detection of common taint patterns in agent code.

Propagation is tracked within a function, and across ONE direct call to a
function defined in the same file (#96). Cross-file flows, recursion, dynamic
dispatch and calls made through an attribute or a variable remain out of
scope, and are reported as such in each finding's ``limitation`` field.
"""

import ast
import re

# Untrusted input sources
SOURCE_PATTERNS = [
    re.compile(r"\b(?:user_input|user_message|user_query|user_prompt)\b", re.IGNORECASE),
    re.compile(r"\b(?:request\.(?:form|args|json|data|body|params))\b", re.IGNORECASE),
    re.compile(r"\b(?:input\(|raw_input\(|sys\.stdin\.read)\b", re.IGNORECASE),
    re.compile(r"\b(?:response\.(?:text|content|body|json))\b", re.IGNORECASE),
    re.compile(r"\b(?:message\.(?:content|text|body))\b", re.IGNORECASE),
    re.compile(r"\b(?:webhook\.(?:payload|data|body))\b", re.IGNORECASE),
    re.compile(r"\b(?:event\.(?:data|payload|message))\b", re.IGNORECASE),
]

# Sensitive sinks
SINK_PATTERNS = {
    "prompt": re.compile(r"\b(?:prompt|system_prompt|user_prompt|chat_history|messages\.append)\b", re.IGNORECASE),
    "tool_call": re.compile(r"\b(?:tool_call|invoke_tool|call_tool|execute_tool)\b", re.IGNORECASE),
    "shell": re.compile(r"\b(?:subprocess|os\.system|popen|exec\(|eval\()\b", re.IGNORECASE),
    # The trailing \b this pattern used to carry could never match: it sat
    # after the closing quote of the mode string, and the next character is
    # always ')' — two non-word characters, so no boundary exists. The rule
    # was unreachable, which is why #96's acceptance criterion could not be
    # met without this. Found while wiring interprocedural tracking.
    "file_write": re.compile(r"\bopen\([^)]*[\"'](?:w|a|x)[bt+]*[\"']", re.IGNORECASE),
    "http_request": re.compile(r"\b(?:requests\.(?:get|post|put|delete)|httpx\.)\b", re.IGNORECASE),
    "database": re.compile(r"\b(?:execute|cursor\.execute|query)\b", re.IGNORECASE),
}

# Variable assignment patterns for tracking propagation
ASSIGNMENT_RE = re.compile(r"(\w+)\s*=\s*(\w+)")

# Variable prefixes that indicate test fixtures, examples, or placeholder data.
# Sources matching these prefixes are skipped to reduce false positives.
_PLACEHOLDER_PREFIXES = (
    "test_", "example_", "dummy_", "mock_", "fake_", "sample_",
    "fixture_", "stub_", "temp_", "tmp_",
)


def _find_sources(content):
    """Find untrusted input sources in file content."""
    sources = []
    for i, line in enumerate(content.splitlines(), 1):
        for pattern in SOURCE_PATTERNS:
            match = pattern.search(line)
            if match:
                var_name = match.group(0)
                # Skip variables that look like test fixtures or placeholders
                base = var_name.split(".")[0].split("(")[0].lower()
                if any(base.startswith(p) for p in _PLACEHOLDER_PREFIXES):
                    continue
                sources.append({
                    "line": i,
                    "variable": var_name,
                    "source_text": line.strip(),
                })
    return sources


def _find_sinks(content):
    """Find sensitive sinks in file content."""
    sinks = []
    for i, line in enumerate(content.splitlines(), 1):
        for sink_type, pattern in SINK_PATTERNS.items():
            match = pattern.search(line)
            if match:
                sinks.append({
                    "line": i,
                    "sink_type": sink_type,
                    "sink_text": line.strip(),
                })
    return sinks


def _track_propagation(content, sources, sinks):
    """Heuristic propagation tracking from sources to sinks.

    Uses simple variable name matching across lines to track how
    untrusted input variables flow through assignments to sinks.
    """
    findings = []
    lines = content.splitlines()

    for source in sources:
        source_var = source["variable"]
        # Clean up variable name (remove method calls)
        base_var = source_var.split(".")[0].split("(")[0]

        for sink in sinks:
            sink_line = sink["line"]
            source_line = source["line"]

            # Skip if sink is before source
            if sink_line <= source_line:
                continue

            # Check if source variable appears in sink line
            sink_text = sink["sink_text"]
            if re.search(rf"\b{re.escape(base_var)}\b", sink_text):
                findings.append({
                    "source_line": source_line,
                    "source_var": base_var,
                    "sink_line": sink_line,
                    "sink_type": sink["sink_type"],
                    "source_text": source["source_text"],
                    "sink_text": sink_text,
                })
                continue

            # Check intermediate lines for variable reassignment
            for check_line in range(source_line, min(sink_line, source_line + 20)):
                if check_line >= len(lines):
                    break
                line_text = lines[check_line]
                assign_match = ASSIGNMENT_RE.search(line_text)
                if assign_match:
                    lhs, rhs = assign_match.groups()
                    if rhs == base_var and re.search(rf"\b{re.escape(lhs)}\b", sink_text):
                        findings.append({
                            "source_line": source_line,
                            "source_var": base_var,
                            "sink_line": sink_line,
                            "sink_type": sink["sink_type"],
                            "source_text": source["source_text"],
                            "sink_text": sink_text,
                            "intermediate_var": lhs,
                        })

    return findings


def _same_file_call_graph(content):
    """Map same-file functions and the direct calls into them (#96).

    Returns ``(functions, calls)`` where ``functions`` maps a function name to
    its positional parameter names and body line span, and ``calls`` is a list
    of direct call sites with the plain-name arguments they were given.

    Deliberately shallow. Only ``def``/``async def`` at any nesting level, only
    calls written as a bare name, and only arguments that are bare names are
    considered — a call through an attribute (``obj.method(x)``), a variable
    holding a function, or a computed argument is not resolved. That keeps the
    pass conservative in the direction that matters: it can miss a real flow,
    but it will not invent a callee.

    Returns ``(None, None)`` when the file does not parse. The analyzer is run
    over whatever is on disk, which includes files mid-edit and Python 2, and a
    syntax error must not take the whole analyzer down.
    """
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError):
        return None, None

    functions = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", None)
            if end is None:  # pragma: no cover - Python < 3.8 shape
                continue
            functions[node.name] = {
                "params": [a.arg for a in node.args.args],
                "start": node.lineno,
                "end": end,
            }

    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name):
            continue
        positional = [
            arg.id if isinstance(arg, ast.Name) else None for arg in node.args
        ]
        keywords = {
            kw.arg: kw.value.id
            for kw in node.keywords
            if kw.arg and isinstance(kw.value, ast.Name)
        }
        calls.append({
            "callee": node.func.id,
            "line": node.lineno,
            "positional": positional,
            "keywords": keywords,
        })

    return functions, calls


def _track_interprocedural(content, sources, sinks):
    """Follow taint one call deep, within the same file (#96).

    The intraprocedural pass requires the sink to appear *after* the source
    line. That is wrong across a call boundary and not by a little: a helper is
    usually defined ABOVE the code that calls it, so its sinks sit at lower line
    numbers than the tainted argument. This pass therefore does not apply that
    ordering rule to the callee body — the ordering that matters is
    source-before-CALL, which is checked here.

    One level only, and no recursion: a call inside the callee is not followed.
    """
    functions, calls = _same_file_call_graph(content)
    if not functions or not calls:
        return []

    findings = []
    for source in sources:
        base_var = source["variable"].split(".")[0].split("(")[0]
        if not base_var.isidentifier():
            continue

        for call in calls:
            # The taint has to exist before it can be passed.
            if call["line"] < source["line"]:
                continue
            callee = functions.get(call["callee"])
            if callee is None:
                continue

            # Which parameter did the tainted variable land on?
            tainted_params = [
                callee["params"][index]
                for index, arg in enumerate(call["positional"])
                if arg == base_var and index < len(callee["params"])
            ]
            tainted_params += [
                name for name, value in call["keywords"].items()
                if value == base_var and name in callee["params"]
            ]
            if not tainted_params:
                continue

            for sink in sinks:
                if not (callee["start"] <= sink["line"] <= callee["end"]):
                    continue
                if not any(
                    re.search(rf"\b{re.escape(param)}\b", sink["sink_text"])
                    for param in tainted_params
                ):
                    continue
                findings.append({
                    "source_line": source["line"],
                    "source_var": base_var,
                    "sink_line": sink["line"],
                    "sink_type": sink["sink_type"],
                    "source_text": source["source_text"],
                    "sink_text": sink["sink_text"],
                    "via_call": call["callee"],
                    "call_line": call["line"],
                })

    return findings


def _finding(rule_id, rule, message, path, line, evidence=None):
    """Create a data-flow finding dict, deriving severity/owasp from the rule."""
    return {
        "rule_id": rule_id,
        "evidence_type": "static-pattern",  # #94 - line-level taint heuristic over source text
        "severity": rule.get("severity", "high"),
        "message": message,
        "file": path,
        "line": line,
        "owasp_llm": rule.get("owasp_llm", "LLM01"),
        "evidence": evidence or message,
        "reason": "Untrusted input propagates into sensitive sink",
        "risk_category": "Safety",
        "affected_framework": "generic",
        "affected_capability": "Data Flow",
        "score_contribution": int(rule.get("score_contribution", 15)),
        "remediation": rule.get("remediation") or (
            "Sanitize untrusted input before use in prompts, tool calls, or shell commands."
        ),
        "confidence": "heuristic",
        "scope": "static-analysis",
        "limitation": (
            "Line-level proxy heuristic. Follows taint one direct call deep "
            "within a single file (#96); does NOT cross files, follow "
            "recursion, resolve dynamic dispatch, or resolve a call made "
            "through an attribute or a variable. May miss indirect "
            "propagation or produce false positives on dynamic constructs."
        ),
    }


class DataFlowAnalyzer:
    """Detects untrusted input propagation into sensitive sinks.

    Uses line-level proxy heuristics to track how user-controlled data
    flows through code into prompts, tool arguments, shell commands,
    and other sensitive operations.
    """

    name = "dataflow"

    def run(self, file_cache, rules, agent_models=None, components=None):
        findings = []
        rule_map = {r.get("id"): r for r in (rules or [])}
        seen = set()

        for path, content in (file_cache or {}).items():
            # Only analyze Python sources: the sink/source patterns are
            # language-specific and would otherwise false-positive on JSON/YAML
            # config files that merely contain keys like "prompt" or "request".
            if not path.endswith(".py"):
                continue
            if not content:
                continue

            sources = _find_sources(content)
            sinks = _find_sinks(content)

            if not sources or not sinks:
                continue

            propagations = _track_propagation(content, sources, sinks)
            # #96 - one call deep, same file. Appended rather than merged: the
            # dedupe key below already collapses a flow both passes find.
            propagations += _track_interprocedural(content, sources, sinks)

            for prop in propagations:
                key = (path, prop["source_line"], prop["sink_line"], prop["sink_type"])
                if key in seen:
                    continue
                seen.add(key)

                rule_id = f"DATAFLOW_{prop['sink_type']}"
                rule = rule_map.get(rule_id, {})
                findings.append(_finding(
                    rule_id=rule_id,
                    rule=rule,
                    message=(
                        f"Observation: variable '{prop['source_var']}' (line "
                        f"{prop['source_line']}) appears in {prop['sink_type']} "
                        f"at line {prop['sink_line']} — heuristic propagation "
                        f"(not verified at runtime)"
                    ),
                    path=path,
                    line=prop["sink_line"],
                    evidence=(
                        f"source:{prop['source_var']}@L{prop['source_line']} -> "
                        + (
                            f"call:{prop['via_call']}()@L{prop['call_line']} -> "
                            if prop.get("via_call")
                            else ""
                        )
                        + f"sink:{prop['sink_type']}@L{prop['sink_line']}"
                    ),
                ))

        return findings
