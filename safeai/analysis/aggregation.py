"""Multi-parser output aggregation and capability deduplication.

When multiple framework parsers match the same file (e.g. a LangGraph
file also imports LangChain), this module merges their outputs by
deduplicating named artifacts (agents, tools, workflows, etc.) using
case-insensitive name keys and retaining the highest confidence per
artifact from any contributing parser.
"""


def _as_items(values):
    """Normalize heterogeneous values into a list of dicts with ``name`` and ``evidence``."""
    out = []
    for value in values or []:
        if isinstance(value, dict):
            out.append(value)
        else:
            out.append({"name": str(value), "evidence": str(value)})
    return out


def _merge_named_items(items, framework, parser_confidence):
    """Merge a list of named items from one framework parse result.

    Items are keyed by case-insensitive name. Conflicting items from
    the same framework keep the highest confidence; subsequent entries
    accumulate evidence and provenance.
    """
    merged = {}
    for item in _as_items(items):
        name = item.get("name") or item.get("id") or item.get("evidence")
        if not name:
            continue
        key = str(name).lower()
        existing = merged.get(key)
        evidence = item.get("evidence") or str(name)
        confidence = float(item.get("confidence", parser_confidence))
        source = item.get("source", "ast")
        if not existing:
            merged[key] = {
                "name": name,
                "evidence": [evidence],
                "frameworks": [framework],
                "provenance": [{
                    "framework": framework,
                    "source": source,
                    "confidence": confidence,
                    "evidence": evidence,
                }],
                "confidence": confidence,
            }
            continue
        if framework not in existing["frameworks"]:
            existing["frameworks"].append(framework)
        if evidence not in existing["evidence"]:
            existing["evidence"].append(evidence)
        existing["provenance"].append({
            "framework": framework,
            "source": source,
            "confidence": confidence,
            "evidence": evidence,
        })
        existing["confidence"] = max(existing["confidence"], confidence)
    return list(merged.values())


def aggregate_parser_models(per_file_results):
    """Merge parser results for each file into a single unified model per file.

    Handles the case where multiple frameworks are detected in the same
    source file by merging named artifacts and accumulating provenance
    metadata from each contributing parser.
    """
    unified_models = []
    for path, parser_results in per_file_results.items():
        frameworks = []
        methods = set()
        framework_confidences = {}
        artifacts = {
            "agents": [],
            "workflows": [],
            "planners": [],
            "memory": [],
            "tools": [],
            "prompts": [],
            "models": [],
            "external_services": [],
            "skills": [],
            "relationships": [],
            "capabilities": [],
        }

        for result in parser_results:
            framework = result.get("framework")
            if framework and framework not in frameworks:
                frameworks.append(framework)
            parser_conf = float(result.get("parser_confidence", 0.65))
            if framework:
                framework_confidences[framework] = max(framework_confidences.get(framework, 0.0), parser_conf)
            methods.add(result.get("discovery_method", "regex"))

            for key in ["agents", "workflows", "planners", "memory", "tools", "prompts", "models", "external_services", "skills", "relationships", "capabilities"]:
                values = result.get(key)
                if not values:
                    continue
                if isinstance(values, list):
                    artifacts[key].extend(values)
                else:
                    artifacts[key].append(values)

        merged_artifacts = {}
        for key in ["agents", "workflows", "planners", "memory", "tools", "prompts", "models", "external_services", "skills"]:
            combined = []
            for result in parser_results:
                values = result.get(key) or []
                framework = result.get("framework", "unknown")
                parser_conf = float(result.get("parser_confidence", 0.65))
                combined.extend(_merge_named_items(values, framework, parser_conf))

            dedup = {}
            for item in combined:
                k = str(item.get("name", "")).lower()
                if not k:
                    continue
                if k not in dedup:
                    dedup[k] = item
                    continue
                existing = dedup[k]
                existing["confidence"] = max(existing["confidence"], item.get("confidence", 0.0))
                for f in item.get("frameworks", []):
                    if f not in existing["frameworks"]:
                        existing["frameworks"].append(f)
                for ev in item.get("evidence", []):
                    if ev not in existing["evidence"]:
                        existing["evidence"].append(ev)
                existing["provenance"].extend(item.get("provenance", []))
            merged_artifacts[key] = list(dedup.values())

        unified_models.append({
            "file": path,
            "frameworks": frameworks,
            "framework_confidence": framework_confidences,
            "discovery_methods": sorted(list(methods)),
            "artifacts": merged_artifacts,
            "relationships": artifacts["relationships"],
            "capabilities": aggregate_capabilities(artifacts["capabilities"]),
        })
    return unified_models


def aggregate_capabilities(capabilities):
    """Merge and deduplicate capability entries from multiple sources.

    Capabilities are keyed by ``(name_lower, category_lower)``. When
    duplicates exist the highest confidence and risk weight are kept,
    and evidence, sources, and provenance are accumulated.
    """
    merged = {}
    for cap in capabilities or []:
        name = str(cap.get("name", "capability"))
        category = cap.get("category", "Capability")
        key = (name.lower(), str(category).lower())
        conf = float(cap.get("confidence", 0.6))
        framework = cap.get("source_framework")
        evidence = cap.get("evidence") or name
        source = cap.get("source", "ast")
        resolved = cap.get("resolved_definition")
        if key not in merged:
            merged[key] = {
                "name": name,
                "category": category,
                "confidence": conf,
                "source_frameworks": [framework] if framework else [],
                "evidence": [evidence],
                "sources": [source],
                "resolved_definitions": [resolved] if resolved else [],
                "risk_weight": float(cap.get("risk_weight", 1.0)),
                "provenance": [{
                    "framework": framework,
                    "confidence": conf,
                    "source": source,
                    "evidence": evidence,
                    "resolved_definition": resolved,
                }],
            }
            continue
        item = merged[key]
        item["confidence"] = max(item["confidence"], conf)
        item["risk_weight"] = max(item["risk_weight"], float(cap.get("risk_weight", 1.0)))
        if framework and framework not in item["source_frameworks"]:
            item["source_frameworks"].append(framework)
        if evidence and evidence not in item["evidence"]:
            item["evidence"].append(evidence)
        if source and source not in item["sources"]:
            item["sources"].append(source)
        if resolved and resolved not in item["resolved_definitions"]:
            item["resolved_definitions"].append(resolved)
        item["provenance"].append({
            "framework": framework,
            "confidence": conf,
            "source": source,
            "evidence": evidence,
            "resolved_definition": resolved,
        })
    return list(merged.values())
