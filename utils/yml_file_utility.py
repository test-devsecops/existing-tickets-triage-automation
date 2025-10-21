import csv, json, yaml

def load_map(path: str, parent_field: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    # supports either {fields:{...}} or a flat {...}
    return cfg.get(parent_field, cfg)

def build_payload(values: dict, fmap: dict, passthrough=("summary","description")) -> dict:
    out = {}
    # keep built-ins if present (remove passthrough if you truly want *only* custom fields)
    for k in passthrough:
        if k in values and values[k] not in ("", None):
            out[k] = str(values[k])

    # map custom fields
    for src, dst in fmap.items():
        if src in values and values[src] not in ("", None):
            out[dst] = values[src]

    return {"fields": out}
