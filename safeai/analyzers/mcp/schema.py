"""MCP schema definitions for supported versions (v1.0 and v1.1).

Each version defines required fields, optional fields, and type
constraints used by the validator and compatibility resolver.
"""

SCHEMA_VERSIONS = {
    "1.0": {
        "required": ["servers", "tools", "resources", "transports"],
        "optional": ["clients", "prompts", "endpoints", "auth", "permissions", "version"],
        "object_rules": {
            "servers": "list",
            "tools": "list",
            "resources": "list",
            "transports": "list",
        },
    },
    "1.1": {
        "required": ["servers", "tools", "resources", "transports", "auth", "permissions"],
        "optional": ["clients", "prompts", "endpoints", "version", "governance"],
        "object_rules": {
            "servers": "list",
            "tools": "list",
            "resources": "list",
            "transports": "list",
            "permissions": "dict_or_list",
        },
    },
}

DEFAULT_SCHEMA_VERSION = "1.1"
