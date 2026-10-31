"""Dependency declarations that must match what the server actually uses."""

import tomllib
from pathlib import Path

_ROOT = Path(__file__).parent.parent
_PYPROJECT = _ROOT / "pyproject.toml"


def test_httpx_is_not_declared() -> None:
    """mcp 2.x depends on ``httpx2``, never ``httpx``.

    Nothing in ``src/`` or ``tests/`` imports ``httpx``, and nothing else
    in the tree pulls it: starlette wants it only under a ``full`` extra
    this project does not install. Twin of rstierli/fortimanager-mcp#95.
    """
    data = tomllib.loads(_PYPROJECT.read_text())
    # Match the name exactly. A bare ``startswith("httpx")`` would also fire
    # on a future ``httpx2`` floor.
    declared = [
        e
        for e in data["project"]["dependencies"]
        if e == "httpx"
        or e.startswith(("httpx>", "httpx=", "httpx<", "httpx!", "httpx~", "httpx["))
    ]
    assert declared == [], f"httpx is declared but unused: {declared}"


def test_noise_suppression_names_the_client_that_ships() -> None:
    """The suppression must name ``httpx2``, the client mcp 2.x actually uses.

    Under mcp 1.x this named ``httpx``; 2.x logs under ``httpx2``
    (``httpx2/_client.py``), so the old name silenced a logger this tree
    no longer has.
    """
    source = (_ROOT / "src" / "fortianalyzer_mcp" / "utils" / "config.py").read_text()
    assert 'getLogger("httpx2")' in source
    assert 'getLogger("httpx")' not in source
