"""Reduce discovery.json to a value-free schema reference.

The raw discovery dump is genuinely useful while writing resources, but it
contains live LAN inventory (DHCP lease hostnames and MAC addresses) and the
WAN public address. Only the SHAPE is needed in version control, so this
renders types instead of values and keeps a single representative element for
each list.

Usage: python schemagen.py   ->   schema.json
"""
import json


def shape(v, depth=0):
    if depth > 6:
        return "..."
    if isinstance(v, dict):
        return {k: shape(v[k], depth + 1) for k in sorted(v)}
    if isinstance(v, list):
        if not v:
            return []
        # One representative element is enough to convey the element type.
        return [shape(v[0], depth + 1)]
    if isinstance(v, bool):
        return "bool"
    if isinstance(v, int):
        return "int"
    if isinstance(v, float):
        return "float"
    if v is None:
        return "null"
    return "string"


def main():
    data = json.load(open("discovery.json", encoding="utf-8"))
    out = {}
    for method in sorted(data):
        if method.startswith("_"):
            out[method] = data[method]
            continue
        entry = data[method]
        if "error" in entry:
            out[method] = {"error": entry["error"]}
        else:
            out[method] = {"result": shape(entry.get("result"))}
    with open("schema.json", "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, sort_keys=True)
    print("wrote schema.json (%d methods)" % len(out))


if __name__ == "__main__":
    main()
