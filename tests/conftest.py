"""Shared fixtures for the policy test suites."""

from __future__ import annotations

import shutil

import pytest

OPA = shutil.which("opa")


@pytest.fixture(scope="session")
def opa() -> str:
    """The opa binary, required rather than optional.

    Compiling and evaluating a generated policy is the coverage most worth
    having, so its absence fails instead of quietly reporting a green suite
    that never checked a policy at all.
    """
    if OPA is None:
        pytest.fail(
            "opa is not on PATH; install it from "
            "https://www.openpolicyagent.org/docs/#running-opa"
        )
    return OPA
