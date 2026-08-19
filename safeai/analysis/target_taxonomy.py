"""Target Taxonomy Engine (CE 1.5 completion).

Aggregates external-network capabilities into explicit destination
buckets: Database, Object Storage, SaaS APIs, and other categories.
Surfaces as a first-class report view in HTML and JSON output.
"""

# Taxonomy buckets: category -> keywords that identify the target type
_TAXONOMY = {
    "database": {
        "keywords": {
            "databases", "database", "sql", "postgres", "mysql", "sqlite",
            "redis", "mongo", "mongodb", "cassandra", "dynamodb", "cosmosdb",
            "firestore", "bigquery", "snowflake", "redshift", "aurora",
        },
        "display_name": "Database",
    },
    "object_storage": {
        "keywords": {
            "s3", "blob", "storage", "gcs", "azure_blob", "minio",
            "bucket", "object_storage", "cloud_storage",
        },
        "display_name": "Object Storage",
    },
    "saas_api": {
        "keywords": {
            "api", "http", "https", "rest", "graphql", "webhook",
            "slack", "github", "gitlab", "jira", "confluence",
            "salesforce", "hubspot", "stripe", "twilio", "sendgrid",
            "mailgun", "discord", "teams", "zoom", "notion",
        },
        "display_name": "SaaS APIs",
    },
    "cloud_service": {
        "keywords": {
            "aws", "azure", "gcp", "google_cloud", "cloud",
            "lambda", "functions", "azure_functions", "cloud_run",
        },
        "display_name": "Cloud Services",
    },
    "messaging": {
        "keywords": {
            "kafka", "rabbitmq", "sqs", "pubsub", "redis_queue",
            "nats", "pulsar", "message_queue", "event_bus",
        },
        "display_name": "Messaging",
    },
}


def _classify_capability(cap):
    """Classify a capability into a taxonomy bucket."""
    name = str(cap.get("name") or "").lower()
    category = str(cap.get("category") or "").lower().replace(" ", "_")

    for bucket_id, bucket in _TAXONOMY.items():
        if name in bucket["keywords"] or category in bucket["keywords"]:
            return bucket_id
        # Check stems (e.g., "databases" matches "database")
        stem = name.rstrip("s")
        if stem in bucket["keywords"]:
            return bucket_id

    return "other"


def build_target_taxonomy(report):
    """Build a target taxonomy from the tool surface and MCP capabilities.

    Returns a dict mapping bucket IDs to lists of tool entries, plus a
    summary with counts per bucket.
    """
    taxonomy = {bucket_id: [] for bucket_id in _TAXONOMY}
    taxonomy["other"] = []

    seen = set()

    # From tool surface (per-tool attribution)
    for entry in report.get("tool_surface") or []:
        tool_key = entry.get("tool_key", "")
        for cap in entry.get("capabilities") or []:
            bucket = _classify_capability(cap)
            # Only include external-network related capabilities
            if bucket in ("database", "object_storage", "saas_api",
                          "cloud_service", "messaging"):
                cap_key = (tool_key, cap.get("name"))
                if cap_key not in seen:
                    seen.add(cap_key)
                    taxonomy[bucket].append({
                        "tool_key": tool_key,
                        "capability": cap.get("name"),
                        "access_mode": cap.get("access_mode"),
                        "category": cap.get("category"),
                        "inferred": cap.get("inferred", False),
                    })

    # From MCP capabilities (aggregated)
    for cap in report.get("mcp_capabilities") or []:
        bucket = _classify_capability(cap)
        if bucket in ("database", "object_storage", "saas_api",
                       "cloud_service", "messaging"):
            cap_key = ("mcp", cap.get("name"))
            if cap_key not in seen:
                seen.add(cap_key)
                taxonomy[bucket].append({
                    "tool_key": "mcp",
                    "capability": cap.get("name"),
                    "access_mode": cap.get("access_mode"),
                    "category": cap.get("category"),
                    "inferred": cap.get("inferred", False),
                })

    summary = {
        bucket_id: len(entries) for bucket_id, entries in taxonomy.items()
    }
    summary["total"] = sum(summary.values())

    # Make output deterministic: sort entries in each bucket and sort summary keys
    sorted_buckets = {}
    for bucket_id in list(_TAXONOMY.keys()) + ["other"]:
        entries = taxonomy.get(bucket_id, [])
        entries.sort(key=lambda e: (str(e.get("tool_key")), str(e.get("capability")), str(e.get("access_mode")), str(e.get("category"))))
        sorted_buckets[bucket_id] = entries

    sorted_summary = dict(sorted(summary.items()))
    sorted_display_names = dict(sorted({
        bucket_id: bucket["display_name"]
        for bucket_id, bucket in _TAXONOMY.items()
    }.items()))

    return {
        "buckets": sorted_buckets,
        "summary": sorted_summary,
        "bucket_display_names": sorted_display_names,
    }
