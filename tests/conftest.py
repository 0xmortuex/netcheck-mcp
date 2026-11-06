from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import pytest

sys.path.insert(0, os.path.dirname(__file__))

pytest.importorskip("cryptography", reason="tests mint certificates with cryptography (pip install '.[test]')")

import lab  # noqa: E402
from netcheck_mcp.guard import Policy  # noqa: E402


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def pki(tmp_path: Any) -> lab.Pki:
    return lab.Pki(tmp_path)


@pytest.fixture
def policy(pki: lab.Pki) -> Policy:
    """Local targets allowed, local root CA trusted (and nothing else)."""
    return Policy(allow_private=True, cafile=pki.root_file, connect_timeout=3.0, total_timeout=10.0)


@pytest.fixture
def strict(policy: Policy) -> Policy:
    return replace(policy, allow_private=False)


@pytest.fixture
def tls_server(pki: lab.Pki) -> Iterator[Any]:
    """Factory: tls_server(leaf, with_intermediate=True, ...) -> WebLab"""
    made: list[lab.WebLab] = []

    def factory(leaf: lab.Ident, with_intermediate: bool = True, **ctx_kw: Any) -> lab.WebLab:
        chain, key = pki.files(leaf, with_intermediate=with_intermediate)
        srv = lab.WebLab(lab.server_ctx(chain, key, **ctx_kw))
        made.append(srv)
        return srv

    yield factory
    for s in made:
        s.close()


@pytest.fixture
def web() -> Iterator[lab.WebLab]:
    srv = lab.WebLab()
    yield srv
    srv.close()


@pytest.fixture
def dns() -> Iterator[lab.DnsLab]:
    srv = lab.DnsLab()
    yield srv
    srv.close()
