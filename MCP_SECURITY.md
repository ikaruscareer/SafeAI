# SafeAI — MCP Security Analysis

## What is MCP?

The **Model Context Protocol (MCP)** is a protocol for connecting AI agents to external tools, resources, and services. MCP exposes agent capabilities over a network protocol, allowing agents to discover and invoke tools dynamically.

MCP configurations typically define:
- **Servers** — MCP server endpoints
- **Clients** — MCP client connections
- **Tools** — Executable operations available to agents
- **Resources** — Data sources accessible to agents
- **Prompts** — Prompt templates for agent interactions
- **Transports** — Communication protocols (HTTP, stdio)
- **Authentication** — Access control for MCP operations
- **Permissions** — Fine-grained access controls

## Why MCP Security Matters

MCP is a significant security surface because:

1. **Network exposure** — MCP servers may be reachable over the network
2. **Tool escalation** — MCP tools can provide broad capabilities (shell, filesystem)
3. **Authentication bypass** — Missing or weak auth allows unauthorized tool invocation
4. **Data leakage** — MCP resources may expose sensitive data
5. **Supply chain risk** — MCP configurations may reference external endpoints
6. **Permission sprawl** — Without permissions, any client can use any tool

## What SafeAI Detects

SafeAI performs static analysis of MCP configurations found in your project. It identifies:

### MCP Assets

| Asset | Detection Method | Description |
|-------|-----------------|-------------|
| MCP Servers | JSON/YAML config parsing | Server endpoint definitions |
| MCP Clients | JSON/YAML config parsing | Client connection definitions |
| MCP Tools | JSON/YAML config parsing | Tool definitions and capabilities |
| MCP Resources | JSON/YAML config parsing | Resource/asset definitions |
| MCP Prompts | JSON/YAML config parsing | Prompt template definitions |
| MCP Transports | JSON/YAML config parsing | Communication protocol definitions |
| MCP Endpoints | JSON/YAML config parsing | Network endpoint definitions |

### Configuration Validation

SafeAI validates MCP configurations against versioned schemas (v1.0, v1.1):

| Rule | Description | Severity |
|------|-------------|----------|
| Required fields | Missing required sections (servers, tools, resources, transports) | Medium |
| Type validation | Fields must be expected types (e.g., `tools` must be a list) | Medium |
| Endpoint type | Endpoint entries must be strings | Low |

### Authentication Analysis

| Finding | Trigger | Severity |
|---------|---------|----------|
| Missing authentication | No `auth` or `authentication` field | High |
| Weak authentication | Auth set to `none`, `anonymous`, or `disabled` | High |

### Permission Analysis

| Finding | Trigger | Severity |
|---------|---------|----------|
| Missing permissions | No `permissions` field | High |

### Endpoint Security

| Finding | Trigger | Severity |
|---------|---------|----------|
| Exposed endpoint | HTTP (non-TLS), `0.0.0.0`, or wildcard host | High |

### Secret Detection

| Finding | Trigger | Severity |
|---------|---------|----------|
| Hardcoded secret | API key or token value in configuration | Critical |

### Dangerous Tool Detection

| Finding | Trigger | Severity |
|---------|---------|----------|
| Dangerous tool | Tool name containing `exec`, `shell`, `command`, `subprocess` | High |

### Capability Mapping

SafeAI maps MCP tool, resource, and transport definitions to capability categories:

| MCP Pattern | Detected Capability |
|-------------|-------------------|
| `file`, `filesystem`, `fs` | Filesystem |
| `shell`, `exec`, `command`, `terminal`, `subprocess` | Shell |
| `sql`, `db`, `postgres`, `mysql`, `sqlite` | Databases |
| `http`, `https`, `api`, `request` | External APIs |
| `aws`, `azure`, `gcp`, `s3`, `blob`, `cloud` | Cloud |
| `memory`, `vector`, `embed`, `retrieval` | Memory / RAG |
| `github`, `git` | GitHub |
| `slack` | Slack |
| `smtp`, `email`, `mail` | Email |
| `browser`, `playwright`, `selenium` | Browser |
| `plan`, `planner` | Planner |
| `delegate`, `handoff`, `handover` | Delegation |
| `approval`, `human` | Human Approval |

## Input Formats

SafeAI detects MCP configurations in:

- **JSON files** — Parsed via `json.loads()`
- **YAML/YML files** — Parsed via `yaml.safe_load()`
- **Python files** — Regex detection of `mcp` keyword references
- **File naming** — Files named `mcp.json`, `mcp.yaml`, `mcp.yml` are automatically identified as MCP configurations

## Versioned Schema Validation

SafeAI validates MCP configurations against supported schema versions:

### Schema v1.0

```yaml
mcp:
  servers: []      # required, list
  tools: []        # required, list
  resources: []    # required, list
  transports: []   # required, list
  clients: []      # optional
  prompts: []      # optional
  endpoints: []    # optional
  auth:            # optional
  permissions:     # optional
```

### Schema v1.1

```yaml
mcp:
  version: '1.1'   # optional
  servers: []      # required, list
  tools: []        # required, list
  resources: []    # required, list
  transports: []   # required, list
  auth:            # required
  permissions:     # required, dict or list
  clients: []      # optional
  prompts: []      # optional
  endpoints: []    # optional
  governance:      # optional
```

### Version Resolution

SafeAI resolves the schema version as follows:
1. Check for `version` or `schema_version` field in MCP configuration
2. If absent, check for `version` in parent document
3. Default to schema v1.1

## Example MCP Configurations

### Secure MCP Configuration

```json
{
  "mcp": {
    "version": "1.1",
    "servers": [
      {
        "name": "prod-server",
        "endpoint": "wss://mcp.internal.example.com"
      }
    ],
    "tools": ["read_data", "write_report"],
    "resources": [],
    "transports": ["wss"],
    "auth": "token",
    "permissions": {
      "client_1": ["read_data"],
      "client_2": ["read_data", "write_report"]
    }
  }
}
```

**SafeAI verdict:** No authentication issues. Permissions configured. No dangerous tools. Secure transport (WSS).

### Insecure MCP Configuration

```json
{
  "mcp": {
    "servers": [],
    "tools": ["exec", "shell_command"],
    "resources": ["/etc/passwd", "/var/log/"],
    "transports": ["http"],
    "endpoints": ["http://0.0.0.0:8080"]
  }
}
```

**SafeAI would report:**
- Missing authentication (high)
- Missing permissions (high)
- Exposed endpoint (high)
- Dangerous tools: exec, shell_command (high)
- Schema v1.1: missing required fields `auth`, `permissions`

## Security Recommendations

### 1. Always Configure Authentication

Set `auth` to `token` or `certificate`. Never use `none`, `anonymous`, or `disabled`.

### 2. Define Permissions

Always set `permissions` to control which clients can access which tools and resources.

### 3. Use Secure Transports

Prefer `wss` (WebSocket Secure) or `https` over plain `http` or `stdio`.

### 4. Restrict Endpoints

Avoid binding to `0.0.0.0` or wildcard hosts. Use specific internal IPs or hostnames.

### 5. Avoid Dangerous Tools

Review tool names for `exec`, `shell`, `command`, and `subprocess`. If shell execution is required, implement strict parameter validation and sandboxing.

### 6. Remove Hardcoded Secrets

Never embed API keys or tokens directly in MCP configuration files. Use environment variables or secret managers.

### 7. Implement Governance

For production deployments, add logging, audit trails, and approval workflows as described in the `governance` section.
