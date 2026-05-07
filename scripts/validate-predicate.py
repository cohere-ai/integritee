#!/usr/bin/env python3
"""Validate a predicate JSON against the schema.

Usage:
    python validate-predicate.py predicate.json
    python validate-predicate.py --schema schemas/predicate-v1.schema.json predicate.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:
    print("jsonschema not installed. Run: pip install jsonschema", file=sys.stderr)
    sys.exit(1)

SCHEMA_PATH = Path(__file__).parent.parent / "schemas" / "predicate-v1.schema.json"


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate predicate against schema")
    parser.add_argument("predicate", help="Path to predicate JSON file")
    parser.add_argument("--schema", default=str(SCHEMA_PATH), help="Path to JSON schema")
    args = parser.parse_args()

    schema = json.loads(Path(args.schema).read_text())
    predicate = json.loads(Path(args.predicate).read_text())

    try:
        jsonschema.validate(instance=predicate, schema=schema)
        print(f"VALID: {args.predicate}")
    except jsonschema.ValidationError as e:
        print(f"INVALID: {args.predicate}", file=sys.stderr)
        print(f"  Path: {'.'.join(str(p) for p in e.absolute_path)}", file=sys.stderr)
        print(f"  Error: {e.message}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
