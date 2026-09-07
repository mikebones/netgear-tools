#!/usr/bin/env python3
"""Report how much of each device's API surface this repo actually uses.

Regenerates the numbers in docs/api-coverage.md.

The interesting output is not the percentage - most uncovered routes are for
features this network does not run, and building resources for them would be
noise. It is the NAMES: run this after a firmware upgrade and anything newly
present is worth a look.

Coverage is decided by a plain string search for the quoted route name across
the Go sources. That is deliberately crude: it cannot tell a route used in an
exporter from one used in a resource, and it will match a route name that
happens to appear in a comment. Both are acceptable for a coverage sketch, and
the alternative - parsing Go - would break the first time somebody builds a
route name by concatenation.
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def go_sources(*dirs):
    """Every .go file under the given directories, concatenated."""
    out = []
    for d in dirs:
        for root, _, files in os.walk(os.path.join(ROOT, d)):
            for f in files:
                if f.endswith(".go"):
                    p = os.path.join(root, f)
                    with open(p, encoding="utf-8", errors="replace") as fh:
                        out.append(fh.read())
    return "\n".join(out)


def load(name):
    p = os.path.join(ROOT, "scripts", name)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as fh:
        return json.load(fh)


def report(label, routes, everything, provider, show_missing):
    routes = sorted(set(r for r in routes if r))
    used = [r for r in routes if f'"{r}"' in everything]
    declared = [r for r in routes if f'"{r}"' in provider]
    pct = 100 * len(used) // len(routes) if routes else 0
    print(f"\n{label}")
    print(f"  exposed   {len(routes)}")
    print(f"  in a client {len(used)} ({pct}%)")
    print(f"  in Terraform {len(declared)}")
    if show_missing:
        missing = [r for r in routes if r not in used]
        print(f"  not used:  {', '.join(missing)}")
    return routes


def main():
    show_missing = "--missing" in sys.argv
    everything = go_sources("internal", "cmd")
    provider = go_sources("internal/provider")

    xs = load("xs508tm_routes.json") or {}
    report("XS508TM  (/api/v1/<route>)",
           [v for v in xs.values() if isinstance(v, str)],
           everything, provider, show_missing)

    ms = load("ms510txup_endpoints.json") or {}
    report("MS510TXUP  (cgi ?cmd=<name>)",
           [v["cmd"] for v in ms.values() if isinstance(v, dict) and "cmd" in v],
           everything, provider, show_missing)

    pr = load("discovery.json") or {}
    report("PR60X getters",
           [k for k in pr if k.startswith("get")],
           everything, provider, show_missing)

    # Setters live in their own file: the original sweep only probed get*, so
    # discovery.json contains no setters at all.
    setters = load("pr60x_setters.json") or {}
    names = []
    for key in ("verified", "seen_but_unverified"):
        v = setters.get(key)
        if isinstance(v, dict):
            names += list(v)
        elif isinstance(v, list):
            names += v
    # NOTE: this list came from the UI bundle, which is shared across models
    # and releases. getSSH and getFastPathEngine are both in it and both answer
    # "Method not found" on firmware 3.0.0.105. Probe before building on a name.
    report("PR60X setters  (from the UI bundle, NOT all present on every firmware)",
           names, everything, provider, show_missing)

    print("\nRun with --missing to list the uncovered route names.")


if __name__ == "__main__":
    main()
