"""Entrypoint for the render-ita-rp-policy composite action.

Runs on the runner rather than in the generate-policy image, since it only
fills a template once the ITA policy is uploaded.

Invoked via: python -m generate_policy.rp
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .generate import policy_output_dir, write_outputs
from .ita import RP_POLICY_FILE, render_rp_policy


def main() -> None:
    output = policy_output_dir() / RP_POLICY_FILE
    try:
        render_rp_policy(
            Path(os.environ["RIM_DIR"]),
            os.environ["POLICY_ID"],
            os.environ["POLICY_HASH"],
            output,
        )
    except ValueError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        sys.exit(1)
    write_outputs({"ita-rp-policy-file": str(output)})


if __name__ == "__main__":
    main()
