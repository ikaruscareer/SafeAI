# SafeAI — Capability Reference

This document describes every capability that SafeAI can detect, how detection works, the associated risk, and recommended mitigations.

---

## How Capability Detection Works

SafeAI detects capabilities through a layered approach:

1. **Framework object model** (AST) — Parses framework-specific Python objects (e.g., `Tool()`, `Agent()`, `bind_tools()`) and maps them to capability categories
2. **Configuration analysis** — Parses YAML/JSON configuration files for capability indicators
3. **Import graph resolution** — Tracks symbol origin across files
4. **Regex fallback** — Scans all source files for capability patterns when structured detection is unavailable

Each detected capability includes:
- **Confidence score** (0.0–1.0) — Higher for AST/configuration detection
- **Source** — `ast`, `configuration`, `regex`, or combination
- **Evidence** — Matching source code or configuration excerpt
- **Resolved definition** — Cross-file origin of the capability (when import graph resolves it)
- **Provenance** — All frameworks that contributed to detection

### Confidence Model

Confidence values are **static, per-parser constants**, not statistical estimates:

| Detection method | Typical confidence | Meaning |
|------------------|--------------------|---------|
| AST + import graph resolution | 0.75–0.9 | Symbol was resolved through framework imports |
| Configuration file analysis | 0.8–0.95 | Structured YAML/JSON evidence |
| Regex fallback | 0.45–0.55 | Pattern match without semantic verification |

When multiple frameworks detect the same capability, the highest confidence
wins (confidence arbitration). Treat regex-level findings as leads for manual
review; treat AST-level findings as high-signal.

---

## Capability Index

| # | Capability | Category | Detection Method | Default Severity |
|---|------------|----------|-----------------|------------------|
| 1 | Shell Execution | Shell | AST + Regex | high |
| 2 | Filesystem Access | Filesystem | AST + Regex | medium |
| 3 | Code Execution | Capability | Regex | high |
| 4 | Network / HTTP | External APIs | AST | medium |
| 5 | Database Access | Databases | Regex | medium |
| 6 | Planner / Orchestration | Planner | AST | high |
| 7 | Agent Delegation | Delegation | AST | high |
| 8 | Memory / Checkpoint | Memory | AST | medium |
| 9 | MCP Integration | MCP | Configuration + AST | medium |
| 10 | Cloud Services | Cloud | Configuration | medium |
| 11 | Multi-Agent | Multi-Agent | AST | high |
| 12 | Browser Automation | Browser | Configuration | medium |
| 13 | GitHub Integration | GitHub | Configuration | medium |
| 14 | Slack Integration | Slack | Configuration | medium |
| 15 | Email Integration | Email | Configuration | medium |
| 16 | RAG / Retrieval | RAG | Configuration | medium |
| 17 | Human Approval | Human Approval | Configuration | medium |
| 18 | Autonomous Loops | Autonomy | Regex | high |

---

## Detailed Capability Reference

### 1. Shell Execution

- **Category:** Shell
- **Default Severity:** High
- **Risk Weight:** 1.6
- **OWASP LLM:** LLM06

**Detection:**
- AST: Framework tool definitions containing shell-related keywords (e.g., `subprocess`, `os.system`, `popen`)
- Regex: Lines matching `subprocess`, `os\.system`, `popen` in any source file

**Evidence examples:**
- `subprocess.run("ls")`
- `os.system("rm -rf /")`
- Tool definition with `shell=True`

**Risk:** An agent with shell execution capabilities can run arbitrary operating system commands. This enables data exfiltration, privilege escalation, lateral movement, and persistence.

**Mitigation:**
- Avoid exposing shell execution to agents
- Use parameterized APIs instead of shell commands
- Apply strict input validation and allowlisting
- Use sandboxed execution environments
- Require human approval for shell operations

---

### 2. Filesystem Access

- **Category:** Filesystem
- **Default Severity:** Medium
- **Risk Weight:** 1.2
- **OWASP LLM:** LLM06

**Detection:**
- AST: Tool definitions with filesystem operations (`open()`, `os.remove`, `os.write`, `pathlib`)
- Regex: Lines matching `open(`, `os\.remove`, `os\.write`, `pathlib`

**Evidence examples:**
- `open("/etc/passwd", "r")`
- `with open("secrets.txt") as f:`
- `os.remove("/tmp/data")`

**Risk:** Filesystem access can lead to data exfiltration, credential theft, configuration tampering, and supply chain attacks through file modification.

**Mitigation:**
- Restrict agent filesystem access to dedicated directories
- Implement read-only access where possible
- Audit all file operations
- Use virtual filesystem sandboxes

---

### 3. Code Execution

- **Category:** Capability
- **Default Severity:** High
- **OWASP LLM:** LLM06

**Detection:**
- Regex: Lines matching `exec(`, `eval(`

**Evidence examples:**
- `eval(user_input)`
- `exec("import os; os.system('rm -rf /')")`

**Risk:** Arbitrary code execution gives agents full control over the runtime environment, enabling any operation.

**Mitigation:**
- Never execute untrusted code
- Use sandboxed environments if code execution is required
- Apply strict allowlisting of safe operations

---

### 4. Network / HTTP

- **Category:** External APIs
- **Default Severity:** Medium
- **OWASP LLM:** LLM06

**Detection:**
- AST: Framework tool definitions with HTTP libraries (`requests`, `httpx`, `urllib`)
- Regex: Lines matching `requests`, `httpx`, `urllib`

**Evidence examples:**
- `requests.get("https://api.example.com/data")`
- `httpx.Client()` with tool binding

**Risk:** HTTP access enables data exfiltration, SSRF attacks, external API abuse, and communication with command-and-control endpoints.

**Mitigation:**
- Restrict outbound network access
- Use URL allowlisting
- Implement request rate limiting
- Monitor for anomalous API calls

---

### 5. Database Access

- **Category:** Databases
- **Default Severity:** Medium
- **OWASP LLM:** LLM06

**Detection:**
- Regex: Lines matching `sqlite3`, `psycopg2`, `mysql`, `postgres`, `sqlalchemy`

**Evidence examples:**
- `sqlite3.connect("data.db")`
- Agent tool querying `SELECT * FROM users`

**Risk:** Database access can lead to data breaches, SQL injection, and unauthorized data modification.

**Mitigation:**
- Grant read-only access where possible
- Use parameterized queries
- Implement row-level security
- Audit and log all database operations

---

### 6. Planner / Orchestration

- **Category:** Planner
- **Default Severity:** High
- **OWASP LLM:** LLM06

**Detection:**
- AST: LangGraph `add_edge`, LangChain `Chain`, Semantic Kernel `kernel.invoke`, CrewAI `Task`
- Confidence: 0.75–0.8

**Evidence examples:**
- `g.add_edge(node_a, node_b)`
- `Chain(tools=[...], memory=...)`
- Workflow with tool and memory objects

**Risk:** Planners determine the execution path of agent systems. Unconstrained planners can chain dangerous operations, escalate privileges, or execute multi-step attacks.

**Mitigation:**
- Constrain planner iteration depth
- Implement human-in-the-loop for critical paths
- Monitor planner execution for anomalies
- Apply capability-based access control

---

### 7. Agent Delegation

- **Category:** Delegation
- **Default Severity:** High
- **OWASP LLM:** LLM06

**Detection:**
- AST: OpenAI Agents handoffs, LangChain AgentExecutor, CrewAI task delegation patterns
- Confidence: 0.75–0.8

**Evidence examples:**
- `handoff(agent_b)` in OpenAI Agents
- CrewAI `Task(agent=...)` delegation
- LangChain `AgentExecutor` with multiple agents

**Risk:** Agent delegation allows one agent to pass tasks to another. This can bypass security controls, escalate capabilities, and make audit trails harder to maintain.

**Mitigation:**
- Audit delegation chains
- Restrict delegation to trusted agents
- Maintain unified logging across all agents

---

### 8. Memory / Checkpoint

- **Category:** Memory
- **Default Severity:** Medium
- **OWASP LLM:** LLM06

**Detection:**
- AST: LangGraph `MemorySaver`, LangChain `ConversationBufferMemory`, Semantic Kernel memory objects, OpenAI Agents `memory`
- Confidence: 0.85–0.9

**Evidence examples:**
- `MemorySaver()` in LangGraph
- `ConversationBufferMemory()` in LangChain
- `kernel.add_memory(...)` in Semantic Kernel

**Risk:** Memory across agent sessions can accumulate sensitive data, create compliance issues (data retention), and enable session replay attacks if not properly managed.

**Mitigation:**
- Encrypt in-memory data
- Implement retention policies
- Audit memory contents periodically
- Clear memory after session completion

---

### 9. MCP Integration

- **Category:** MCP
- **Default Severity:** Medium
- **OWASP LLM:** LLM06

**Detection:**
- Configuration: JSON/YAML MCP configuration files
- AST: OpenAI Agents MCP tool references
- Regex: `mcp` keyword in source files

**Evidence examples:**
- MCP JSON/YAML config with servers, tools, resources
- Python references to MCP tools

**Risk:** MCP integrations expose agent capabilities over a network protocol. Unauthenticated MCP endpoints allow arbitrary tool invocation by unauthorized clients.

**Mitigation:** See [MCP_SECURITY.md](MCP_SECURITY.md) for detailed MCP security guidance.

---

### 10. Cloud Services

- **Category:** Cloud
- **Default Severity:** Medium
- **OWASP LLM:** LLM06

**Detection:**
- Configuration: Azure Foundry YAML, AWS Bedrock JSON
- AST: Azure OpenAI, AWS Bedrock model references

**Evidence examples:**
- Azure Foundry YAML with `azure: true`
- Bedrock JSON config
- `AzureChatOpenAI()` or `Bedrock()` model references

**Risk:** Cloud service integration can lead to cost escalation, data residency violations, and cloud credential exposure.

**Mitigation:**
- Restrict cloud resource access to least privilege
- Monitor cloud API usage for anomalies
- Apply budget alerts and spending limits

---

### 11. Multi-Agent

- **Category:** Multi-Agent
- **Default Severity:** High
- **OWASP LLM:** LLM06

**Detection:**
- AST: OpenAI Agents `Agent()`, CrewAI `Agent()`
- Confidence: 0.75

**Evidence examples:**
- Multiple `Agent()` instances in CrewAI
- OpenAI Agents with different agent definitions

**Risk:** Multi-agent systems increase the attack surface. Compromise of one agent can cascade to others through delegation or shared resources.

**Mitigation:**
- Isolate agent runtimes
- Implement cross-agent authentication
- Audit all inter-agent communication

---

### 12. Browser Automation

- **Category:** Browser
- **Default Severity:** Medium
- **OWASP LLM:** LLM06

**Detection:**
- MCP Configuration: Tool definitions containing `browser`, `playwright`, `selenium`
- Framework adapter: Partial support

**Evidence examples:**
- MCP tool with `browser` keyword in resources or tools
- Playwright or Selenium references in MCP config

**Risk:** Browser automation can be used for credential harvesting, UI-based attacks, and data exfiltration through web scraping.

**Mitigation:**
- Restrict browser automation to specific URLs
- Audit browsing sessions
- Never expose browser automation to untrusted agents

---

### 13. GitHub Integration

- **Category:** GitHub
- **Default Severity:** Medium
- **OWASP LLM:** LLM06

**Detection:**
- MCP Configuration: Tool names containing `github`, `git`

**Evidence examples:**
- MCP tool: `github_api`
- MCP resource: `git_repository`

**Risk:** GitHub integrations can read/write repositories, expose secrets, and exfiltrate source code.

**Mitigation:**
- Use read-only tokens
- Restrict repository access
- Audit GitHub API usage

---

### 14. Slack Integration

- **Category:** Slack
- **Default Severity:** Medium
- **OWASP LLM:** LLM06

**Detection:**
- MCP Configuration: Tool names containing `slack`

**Evidence examples:**
- MCP tool: `slack_post_message`
- MCP tool: `slack_read_channel`

**Risk:** Slack integrations can read messages, post as the bot user, and exfiltrate internal communications.

**Mitigation:**
- Restrict Slack bot token scopes
- Audit message posting history

---

### 15. Email Integration

- **Category:** Email
- **Default Severity:** Medium
- **OWASP LLM:** LLM06

**Detection:**
- MCP Configuration: Tool names containing `smtp`, `email`, `mail`

**Evidence examples:**
- MCP tool: `send_email`
- MCP resource: `smtp_config`

**Risk:** Email integrations can send phishing emails, exfiltrate data via email, and compromise email accounts.

**Mitigation:**
- Restrict email sending to allowlisted recipients
- Require human approval for bulk emails

---

### 16. RAG / Retrieval

- **Category:** RAG
- **Default Severity:** Medium
- **OWASP LLM:** LLM06

**Detection:**
- MCP Configuration: Tool/resource names containing `memory`, `vector`, `embed`, `retrieval`

**Evidence examples:**
- MCP resource: `vector_store`
- MCP tool: `retrieve_documents`

**Risk:** RAG systems can expose sensitive documents to unauthorized users through retrieval queries.

**Mitigation:**
- Implement document-level access control
- Audit retrieval queries
- Sanitize documents before indexing

---

### 17. Human Approval

- **Category:** Human Approval
- **Default Severity:** Medium
- **OWASP LLM:** LLM06

**Detection:**
- MCP Configuration: Tool/resource names containing `approval`, `human`
- Framework adapter: Partial support

**Evidence examples:**
- MCP tool: `approval_gate`
- Agent workflow with human approval step

**Risk:** Without human approval, agents can execute high-risk operations autonomously.

**Mitigation:**
- Require human approval for critical operations
- Implement timeouts for approval requests

---

### 18. Autonomous Loops

- **Category:** Autonomy
- **Default Severity:** High
- **OWASP LLM:** LLM06

**Detection:**
- Regex: `while True` combined with agent-related content; `for _ in range(...)` with agent content

**Evidence examples:**
- `while True: agent.run()`
- `for _ in range(100): llm_chain.respond()`

**Risk:** Unbounded autonomous loops can result in infinite execution, cost escalation, and out-of-control agent behavior.

**Mitigation:**
- Impose iteration limits
- Implement timeout and circuit breaker patterns
- Require human approval for long-running loops
