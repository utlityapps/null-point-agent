"""Shared fixtures for the NullPoint test suite."""
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from nullpoint import graph as graph_mod  # noqa: E402


@pytest.fixture()
def infra():
    with open(REPO_ROOT / "fixtures" / "infra.json") as fh:
        return json.load(fh)


@pytest.fixture()
def findings():
    with open(REPO_ROOT / "fixtures" / "cves.json") as fh:
        return json.load(fh)["findings"]


@pytest.fixture()
def solver(infra):
    return graph_mod.InfraGraph(infra)


@pytest.fixture()
def fixtures_dir():
    return str(REPO_ROOT / "fixtures")
