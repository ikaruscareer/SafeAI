# Examples Directory

This directory contains example agent projects for testing SafeAI detections. Each example demonstrates specific framework usage patterns and risk profiles.

---

## Structure

```
examples/
    safe/                   # Examples that should trigger few or no findings
    risky/                  # Examples with deliberate security issues
    multi-agent/            # Multi-agent coordination patterns
    mcp/                    # MCP server and client configurations
    prompts/                # Prompt injection scenarios
    workflows/              # Workflow definition examples
    crewai/                 # CrewAI-specific examples
    langgraph/              # LangGraph-specific examples
    semantic-kernel/        # Semantic Kernel-specific examples
    autogen/                # AutoGen-specific examples
    google-adk/             # Google ADK-specific examples
    n8n/                    # n8n workflow examples
```

---

## What Each Example Should Demonstrate

### `safe/`
- Properly configured agents with timeouts
- Tools with least-privilege permissions
- Authentication configured on endpoints
- No hardcoded secrets
- Human approval gates on sensitive actions

### `risky/`
- Direct user input in prompt strings
- Shell execution with uncontrolled parameters
- Hardcoded API keys and tokens
- Missing authentication on MCP endpoints
- Autonomous loops without iteration limits
- Unrestricted file system access

### `multi-agent/`
- Agent delegation chains
- Supervisor / worker patterns
- Handoff between specialized agents
- Multi-agent with shared memory

### `mcp/`
- MCP server definitions with various transports
- MCP client configurations
- Tool and resource definitions
- Authentication configurations (missing, weak, strong)

### `prompts/`
- System prompt with user input interpolation
- Missing delimiters between system and user content
- Role override attempts ("ignore previous instructions")
- System prompt leakage patterns

### `workflows/`
- Linear workflows
- Conditional branching workflows
- Parallel execution workflows
- Human-in-the-loop approval steps

### Framework-specific (`crewai/`, `langgraph/`, etc.)
- Minimal agent definition
- Agent with tools
- Agent with memory
- Agent with external API calls
- Agent with filesystem access

---

## Running SafeAI on Examples

```bash
# Scan all examples
python -m safeai scan examples/

# Scan a specific category
python -m safeai scan examples/risky/

# Generate report
python -m safeai scan examples/ --sarif examples.sarif --html report.html
```

---

## Adding New Examples

1. Create a subdirectory under the appropriate category
2. Add a `README.md` explaining what the example demonstrates
3. Keep examples focused — each should demonstrate one or two patterns
4. Avoid large files — examples should be minimal and readable
5. Run SafeAI against your example to confirm expected behavior
6. Update `.gitignore` if your example generates output files

---

## Example Contribution Checklist

- [ ] Example is minimal and focused
- [ ] Example includes a README explaining the pattern
- [ ] SafeAI detects expected findings (for risky examples)
- [ ] SafeAI does NOT produce unexpected false positives (for safe examples)
- [ ] Example runs on all supported platforms
