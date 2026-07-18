# SafeAI — Framework Support Reference

This document details the detection approach, discovered artifacts, capabilities, and limitations for each supported AI agent framework.

---

## Framework Support Summary

| Framework | Detection Method | Discovery Depth | Capability Analysis | Status |
|-----------|-----------------|----------------|-------------------|--------|
| LangGraph | AST + regex | Nodes, edges, tools, models, memory | Shell, filesystem, memory, planner | Early Preview |
| CrewAI | AST + regex | Agents, tasks, tools, models, memory | Shell, memory, delegations | Early Preview |
| LangChain | AST + metadata + regex | Agents, chains, tools, memory, models | Shell, memory, planner | Early Preview |
| Semantic Kernel | AST + metadata + regex | Workflows, plugins, memory, models, skills | Shell, memory, planner | Early Preview |
| OpenAI Agents SDK | AST + metadata + regex | Agents, tools, handoffs, MCP | Multi-agent, delegation, MCP | Early Preview |
| Microsoft Agent Framework | AST + config + deps + regex | Agents, workflows, tools, memory, models | Cloud, memory | Early Preview |
| Azure AI Foundry | Configuration | Tools, models from YAML | Cloud | Early Preview |
| Bedrock Agent | Configuration | Tools from JSON | (minimal) | Early Preview |

---

## LangGraph

### Detection Approach

**Priority:** AST → regex fallback

- **Imports:** Detects `langgraph` in Python import statements
- **AST:** Parses `StateGraph`, `add_edge`, `add_node`, and function definitions
- **Dependencies:** `langgraph` in `requirements.txt`, `pyproject.toml`, etc.
- **Regex fallback:** `StateGraph`, `Graph(`, `add_edge` patterns

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Graph nodes | AST function definitions | 0.89 | Agent workflow node functions |
| Workflow edges | AST `add_edge` calls | 0.89 | Graph connection edges |
| Tools | AST `bind_tools`, `tool` calls | 0.85 | Tools bound to graph nodes |
| Models | AST model constructor calls | 0.80 | LLM provider references |
| Memory / Checkpointer | AST `memory`, `checkpointer` keywords | 0.85 | State persistence mechanisms |
| Prompts | AST call names containing "prompt" | 0.75 | Prompt template usage |

### Capabilities Discovered

- **Planner** — Graph execution planning via `add_edge` calls
- **Memory** — Checkpointer and memory objects
- **Shell** — Tool definitions with `subprocess`, `os.system`, `popen`
- **Filesystem** — Tool definitions with `open()`, `os.remove`, `os.write`
- **External APIs** — Model references (`ChatOpenAI`, `AzureChatOpenAI`, `Bedrock`)

### Detection Example

```python
from langgraph import Graph

def node_a(state):
    return state

g = Graph()
g.add_node(node_a)
```

SafeAI detects:
- Framework: `langgraph`
- Node: `node_a`
- Graph construction with `add_node`
- Edge relationships from `add_edge`

---

## CrewAI

### Detection Approach

**Priority:** AST → regex fallback

- **Imports:** Detects `crewai` in Python import statements
- **AST:** Parses `Agent()`, `Task()`, tool references
- **Dependencies:** `crewai` in manifest files
- **Regex fallback:** `Agent(`, `Task(`, `tools=`, `tool=` patterns

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Agents | AST `Agent()` calls | 0.86 | CrewAI agent definitions |
| Tasks | AST `Task()` calls | 0.86 | Task definitions with assignments |
| Tools | AST tool references | 0.80 | Tool bindings in agents/tasks |
| Models | AST model references | 0.80 | LLM provider references |
| Memory | AST "memory" keyword | 0.85 | Memory configuration |

### Capabilities Discovered

- **Multi-Agent** — Multiple `Agent()` instances
- **Planner** — Task-based workflow orchestration
- **Memory** — Memory objects in agent definitions
- **Shell** — Tool definitions with shell operations
- **External APIs** — Model references

### Detection Example

```python
from crewai import Agent, Task

agent = Agent(role="developer")
task = Task(description="analyze code", agent=agent)
```

SafeAI detects:
- Framework: `crewai`
- Agent: `agent`
- Task: `task` with description and agent assignment

---

## LangChain

### Detection Approach

**Priority:** AST → metadata → regex fallback

- **Imports:** Detects `langchain` in Python import statements
- **Dependencies:** `langchain` in manifest files
- **AST:** Parses `AgentExecutor`, `Chain`, `Tool`, `PromptTemplate`, model constructors
- **Regex fallback:** `Tool(`, `PromptTemplate`, `ChatPromptTemplate`

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Agents | AST `AgentExecutor`, agent patterns | 0.88 | Agent executor definitions |
| Workflows | AST Chain, Runnable patterns | 0.75 | Execution chain definitions |
| Tools | AST `Tool()`, tool patterns | 0.80 | Tool registrations |
| Prompts | AST `PromptTemplate` | 0.75 | Prompt template definitions |
| Memory | AST "memory" keyword | 0.90 | Conversation memory objects |
| Models | AST model constructor calls | 0.85 | LLM provider references |
| External Services | AST integration patterns | 0.75 | GitHub, Slack, email, DB integrations |

### Capabilities Discovered

- **Planner** — Chain-based workflow orchestration
- **Delegation** — Agent executor delegation patterns
- **Memory** — Conversation memory objects
- **External APIs** — Model integrations, HTTP tools
- **Shell** — Tool definitions with shell operations
- **Filesystem** — Tool definitions with file operations

### Detection Example

```python
from langchain.agents import AgentExecutor
from langchain.chains import LLMChain

agent = AgentExecutor(agent="zero-shot-react-description", tools=[...])
```

SafeAI detects:
- Framework: `langchain`
- Agent: `AgentExecutor` with tool references
- Chain relationships from constructor arguments

---

## Semantic Kernel

### Detection Approach

**Priority:** AST → metadata → regex fallback

- **Imports:** Detects `semantic_kernel` in Python imports
- **Dependencies:** `semantic-kernel` in manifest files
- **AST:** Parses `Kernel.invoke`, plugins, functions, memory, skill references
- **Regex fallback:** `skill` keyword

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Workflows | AST `kernel.invoke` patterns | 0.86 | Kernel invocation chains |
| Tools | AST function, plugin patterns | 0.80 | Plugin and function references |
| Prompts | AST "prompt" in calls | 0.75 | Prompt references |
| Memory | AST "memory" keyword | 0.90 | Semantic memory references |
| Skills | AST "skill" patterns | 0.80 | Skill definitions |
| Models | AST model constructor calls | 0.85 | OpenAI, Azure, Anthropic references |

### Capabilities Discovered

- **Planner** — Kernel-based orchestration
- **Memory** — Semantic memory connections
- **External APIs** — Model provider integrations

### Detection Example

```python
from semantic_kernel import Kernel

kernel = Kernel()
await kernel.invoke(function, plugin)
```

SafeAI detects:
- Framework: `semantic_kernel`
- Workflow: `kernel.invoke` with function and plugin arguments
- Skills, plugins, and memory from call arguments

---

## OpenAI Agents SDK

### Detection Approach

**Priority:** AST → metadata → regex fallback

- **Imports:** Detects `agents`, `openai` imports with agent patterns
- **Dependencies:** `openai-agents` in manifest files
- **AST:** Parses `Agent()`, tool calls, handoffs, MCP references
- **Regex fallback:** `Agent(` pattern

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Agents | AST `Agent()` calls | 0.87 | Agent definitions |
| Tools | AST tool pattern | 0.80 | Tool registrations |
| Workflows | AST handoff patterns | 0.80 | Agent handoff workflows |
| Memory | AST "memory" keyword | 0.85 | Memory configuration |
| MCP Assets | AST "mcp" keyword | 0.90 | MCP tool references |
| Models | AST model references | 0.85 | GPT, responses, chat.completions |

### Capabilities Discovered

- **Multi-Agent** — Multiple agent instances
- **Delegation** — Handoff-based agent delegation
- **MCP** — MCP tool integration
- **Memory** — Agent memory
- **External APIs** — Model calls

### Detection Example

```python
from agents import Agent, Runner

agent = Agent(name="assistant", instructions="Be helpful")
result = Runner.run(agent, "Hello")
```

SafeAI detects:
- Framework: `openai_agents`
- Agent: with name and instructions
- Runner workflow

---

## Microsoft Agent Framework

### Detection Approach

**Priority:** AST → configuration → dependencies → regex fallback

- **Imports:** Detects `azure.ai.agents`, `microsoft.agent`
- **Dependencies:** `azure-ai-agents`, `azure-ai-projects`
- **AST:** Parses `AgentClient`, tool, run, workflow patterns
- **Configuration:** YAML/JSON files with agent references
- **Regex fallback:** `AgentClient`, `agent` keywords

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Agents | AST agent patterns | 0.85 | Agent client definitions |
| Workflows | AST run, workflow patterns | 0.80 | Agent execution workflows |
| Tools | AST tool, function patterns | 0.80 | Tool/function definitions |
| Prompts | AST "prompt" keyword | 0.75 | Prompt references |
| Memory | AST "memory" keyword | 0.80 | Memory configuration |
| Models | AST model references | 0.85 | Azure OpenAI, GPT references |

### Capabilities Discovered

- **Cloud** — Azure cloud model integration
- **Memory** — Agent memory objects
- **Multi-Agent** — Multiple agent definitions

### Detection Example

```python
from azure.ai.agents import AgentClient

client = AgentClient(endpoint="https://...", credential=credential)
```

SafeAI detects:
- Framework: `microsoft_agent_framework`
- Agent: `AgentClient` with endpoint and credential
- Workflow: run operations

---

## Azure AI Foundry

### Detection Approach

**Priority:** Configuration (YAML/JSON) → dependencies

- **File extension:** `.yaml`, `.yml` files
- **Content:** `azure` keyword in YAML/JSON content
- **Dependencies:** `azure-ai-projects`, `azure-ai-agents` in manifest files

### Artifacts Discovered

| Artifact | Detection | Confidence | Description |
|----------|-----------|-----------|-------------|
| Tools | YAML `tools` or `actions` keys | 0.84 | Tool definitions in config |
| Models | YAML `model`, `models`, `llm`, `deployment` keys | 0.84 | Model references |
| Workflows | YAML `name` key | 0.84 | Agent workflow name |

### Capabilities Discovered

- **Cloud** — Azure cloud service reference

### Detection Example

```yaml
azure: true
name: test-agent
tools: []
```

SafeAI detects:
- Framework: `azure_foundry`
- Tools from `tools` array
- Models from `model`/`llm` keys

---

## Limitations

### Current Constraints

1. **Detection depth is partial**
   - Framework adapters use heuristic object detection rather than full framework-native object model parsing
   - Complex dynamic agent construction may not be fully captured
   - Capability detection relies on naming conventions and may miss unconventional patterns

2. **Cross-file analysis is limited**
   - Import graph resolves symbol origins but does not perform full interprocedural analysis
   - Re-exported symbols through `__init__.py` files are tracked but not deeply resolved

3. **Capability inference needs improvement**
   - Boolean capabilities (e.g., `memory=True`) may not be detected in all frameworks
   - Enum-based tool categories may be missed
   - Some capabilities are only detected through MCP configuration, not framework adapters

4. **False positive risk**
   - Regex fallback patterns may trigger on unrelated variables or documentation strings
   - Capability keywords in comments or documentation may generate findings

5. **JavaScript/TypeScript support**
   - Limited to `package.json` dependency detection
   - No AST-level analysis for non-Python languages

6. **No version-aware framework detection**
   - Framework version is not extracted or compared against known vulnerability databases
   - All detection is version-agnostic
