"""Conservative review of changes to OpenAPI operations and component schemas."""
import yaml

METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
DOC_FIELDS = {"description", "summary", "example", "examples", "externalDocs", "tags"}


def _normalize(value: object) -> object:
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in DOC_FIELDS:
                continue
            if key in {"properties", "schemas"} and isinstance(item, dict):
                result[key] = {name: _normalize(schema) for name, schema in item.items()}
            else:
                result[key] = _normalize(item)
        return result
    return value


def compare_openapi(before: str | None, after: str | None) -> list[str]:
    if after is None:
        return ["OpenAPI contract removed"]
    head = yaml.safe_load(after)
    if not isinstance(head, dict) or not isinstance(head.get("paths"), dict):
        return ["Invalid OpenAPI document"]
    if before is None:
        return []
    base = yaml.safe_load(before)
    if not isinstance(base, dict) or not isinstance(base.get("paths"), dict):
        return ["Invalid base OpenAPI document"]
    errors: list[str] = []
    for route, resource in base["paths"].items():
        new = head["paths"].get(route)
        if not isinstance(new, dict) or not isinstance(resource, dict):
            errors.append(f"Removed or invalid route {route}")
            continue
        for method, operation in resource.items():
            if method in METHODS and isinstance(operation, dict):
                candidate = new.get(method)
                if not isinstance(candidate, dict):
                    errors.append(f"Removed operation {method.upper()} {route}")
                    continue
                for field in set(operation) | set(candidate):
                    if field in DOC_FIELDS:
                        continue
                    if field == "responses" and isinstance(operation.get(field), dict) and isinstance(candidate.get(field), dict):
                        for status, schema in operation[field].items():
                            if status not in candidate[field] or _normalize(schema) != _normalize(candidate[field][status]):
                                errors.append(f"Changed response {status} on {method.upper()} {route}")
                    elif _normalize(operation.get(field)) != _normalize(candidate.get(field)):
                        errors.append(f"Changed {field} on {method.upper()} {route}")
            elif method not in DOC_FIELDS and _normalize(operation) != _normalize(new.get(method)):
                errors.append(f"Changed {method} on {route}")
        if "parameters" not in resource and new.get("parameters"):
            errors.append(f"Added path-level parameters on {route}")
    for group, entries in (base.get("components") or {}).items():
        new_entries = (head.get("components") or {}).get(group, {})
        for name, item in entries.items():
            if name not in new_entries or _normalize(item) != _normalize(new_entries[name]):
                errors.append(f"Changed component {group}/{name}")
    for key in ("openapi", "swagger", "security", "servers", "basePath", "host", "schemes"):
        if base.get(key) != head.get(key):
            errors.append(f"Changed contract {key}")
    return errors
