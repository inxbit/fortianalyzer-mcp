"""No bare multi-condition list may reach the array-dialect endpoints (#146).

dvmdb and task read ``[c1, c2]`` as an OR, not an AND. Measured on
FortiAnalyzer 7.6.7 build 3737: two ``name ==`` conditions returned both
devices, ``not_in`` over two names returned all 17 devices including both
excluded ones, and ``name_filter`` plus ``platform_filter`` returned the union.
Every one still reported ``status: success``. ``[c1, "&&", c2]`` is the
intersection, and ``"||"`` is the explicit OR.

The guard here sits at the pyfmg boundary rather than at the compiler, so it
also catches a tool that builds its filter by hand.
"""

from __future__ import annotations

import ast
import itertools
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

import fortianalyzer_mcp
import fortianalyzer_mcp.tools.dvm_tools as dvm_tools
import fortianalyzer_mcp.tools.system_tools as system_tools
from fortianalyzer_mcp.api.client import FortiAnalyzerClient
from fortianalyzer_mcp.query.filters import FilterCondition, compile_to_array

_SEPARATORS = frozenset({"&&", "||"})


def _is_condition(node: object) -> bool:
    """A ``[field, op, value]`` entry, as opposed to a chain of them."""
    return (
        isinstance(node, list)
        and len(node) == 3
        and isinstance(node[0], str)
        and isinstance(node[1], str)
    )


def _check_chain(chain: object, path: str = "filter") -> None:
    """Fail unless ``chain`` is ``term (sep term)*`` with one separator kind.

    A term is a condition or a nested chain. Mixing ``"&&"`` and ``"||"`` in
    one flat list is refused too: their precedence is undocumented, so a mixed
    chain has to be expressed by nesting.
    """
    assert isinstance(chain, list) and chain, f"{path}: not a non-empty list: {chain!r}"
    assert len(chain) % 2 == 1, (
        f"{path}: {chain!r} is not term, separator, term, ... -- a bare list of "
        "conditions is an OR on the appliance"
    )
    separators = chain[1::2]
    for separator in separators:
        assert isinstance(separator, str) and separator in _SEPARATORS, (
            f"{path}: two terms with no '&&'/'||' between them in {chain!r} -- a bare "
            "list of conditions is an OR on the appliance"
        )
    assert len(set(separators)) <= 1, (
        f"{path}: {chain!r} mixes '&&' and '||' in one flat list; nest instead"
    )
    for index, term in enumerate(chain[0::2]):
        if not _is_condition(term):
            _check_chain(term, f"{path}[{index * 2}]")


class TestTheGuardItself:
    """The checker has to fail on the shape #146 shipped, or it guards nothing."""

    @pytest.mark.parametrize(
        "bad",
        [
            [["name", "==", "a"], ["name", "==", "b"]],
            [["name", "==", "a"], ["name", "==", "b"], ["name", "==", "c"]],
            [["name", "==", "a"], "&&", ["name", "==", "b"], ["mr", "==", 6], ["os_ver", "==", 7]],
            [["a", "==", 1], "&&", ["b", "==", 2], "||", ["c", "==", 3]],
            [[["a", "==", 1], ["a", "==", 2]], "&&", ["b", "==", 2]],
            [],
        ],
    )
    def test_rejects(self, bad: list[Any]) -> None:
        with pytest.raises(AssertionError):
            _check_chain(bad)

    @pytest.mark.parametrize(
        "good",
        [
            [["name", "==", "a"]],
            [["name", "==", "a"], "&&", ["mr", "==", 6]],
            [["a", "==", 1], "||", ["a", "==", 2]],
            [[["a", "==", 1], "||", ["a", "==", 2]], "&&", ["b", "==", 2]],
        ],
    )
    def test_accepts(self, good: list[Any]) -> None:
        _check_chain(good)


#: Conditions that compile on the device vocabulary, one or more entries each.
_DEVICE_POOL = [
    FilterCondition(field="name", op="eq", value="fgt-01"),
    FilterCondition(field="name", op="contains", value="fgt"),
    FilterCondition(field="platform", op="contains", value="VM"),
    FilterCondition(field="os_ver", op="eq", value=7),
    FilterCondition(field="mr", op="gte", value=4),
    FilterCondition(field="conn_status", op="eq", value="up"),
    FilterCondition(field="name", op="not_in", value=["a", "b", "c"]),
    FilterCondition(field="sn", op="not_in", value=["FG100F0000"]),
    FilterCondition(field="name", op="in", value=["a", "b"]),
    FilterCondition(field="os_ver", op="in", value=[6, 7, 8]),
    FilterCondition(field="sn", op="in", value=["FG100F0000"]),
]


@pytest.mark.parametrize("size", [1, 2, 3])
def test_every_compiled_combination_is_a_joined_chain(size: int) -> None:
    for combination in itertools.permutations(_DEVICE_POOL, size):
        entries, _ = compile_to_array(list(combination), "device")
        _check_chain(entries, f"compile_to_array{[c.field for c in combination]}")


#: Tool calls that combine two or more conditions. Each must reach the client
#: as one joined chain; a call that sends a single condition would prove nothing.
_MULTI_CONDITION_CALLS: list[tuple[Any, dict[str, Any]]] = [
    (dvm_tools.search_devices, {"name_filter": "myfw01", "platform_filter": "Syslog"}),
    (dvm_tools.search_devices, {"os_version_filter": "7.6"}),
    (dvm_tools.search_devices, {"os_version_filter": "7.6.7", "connection_status": "up"}),
    (
        dvm_tools.search_devices,
        {
            "filters": [
                FilterCondition(field="name", op="eq", value="myfw01"),
                FilterCondition(field="name", op="eq", value="myfw01-old"),
            ]
        },
    ),
    (
        dvm_tools.search_devices,
        {"filters": [FilterCondition(field="name", op="not_in", value=["myfw01", "myfw01-old"])]},
    ),
    (
        dvm_tools.search_devices,
        {
            "name_filter": "fgt",
            "connection_status": "down",
            "filters": [FilterCondition(field="desc", op="contains", value="branch")],
        },
    ),
    (
        dvm_tools.search_devices,
        {"filters": [FilterCondition(field="name", op="in", value=["myfw01", "myfw01-old"])]},
    ),
    (
        dvm_tools.search_devices,
        {
            "os_version_filter": "7",
            "filters": [FilterCondition(field="mr", op="in", value=[4, 6])],
        },
    ),
    (
        system_tools.list_tasks,
        {
            "filter_state": "done",
            "filters": [FilterCondition(field="title", op="contains", value="report")],
        },
    ),
    (
        system_tools.list_tasks,
        {
            "filters": [
                FilterCondition(field="state", op="eq", value="error"),
                FilterCondition(field="num_err", op="gt", value=0),
            ]
        },
    ),
]


@pytest.mark.parametrize(
    ("tool", "kwargs"),
    _MULTI_CONDITION_CALLS,
    ids=[f"{tool.__name__}-{sorted(kwargs)}" for tool, kwargs in _MULTI_CONDITION_CALLS],
)
async def test_no_bare_multi_condition_list_reaches_the_client(
    tool: Any,
    kwargs: dict[str, Any],
    mock_client: FortiAnalyzerClient,
    mock_fmg_instance: MagicMock,
    configure_mock_responses: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dvm_tools, "_get_client", lambda: mock_client)
    monkeypatch.setattr(system_tools, "_get_client", lambda: mock_client)

    result = await tool(**kwargs)

    assert result["status"] == "success", result
    sent = [call.kwargs["filter"] for call in mock_fmg_instance.get.call_args_list]
    assert sent, "the tool never sent a filter to the appliance"
    for filter_ in sent:
        assert len(filter_) > 1, f"expected a combined filter, got {filter_!r}"
        _check_chain(filter_)
    assert result["filter_applied"] == sent[-1]


def _hand_built_conditions(root: Path) -> list[str]:
    """Every ``[<name>, "<op>", value]`` list literal under ``root``.

    A condition built outside ``compile_to_array`` is how the narrow parameters
    got appended to a bare list: the join is only correct by construction if
    the compiler is the only thing that builds entries. ``api/`` is excluded
    as transport, and its one literal is a fixed single condition that is
    never combined with another; ``query/`` is the compiler itself.
    """
    ops = {"==", "!=", "<", ">", "<=", ">=", "like", "contain", "!contain"}
    found = []
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if relative.parts[0] in {"api", "query"}:
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if (
                isinstance(node, ast.List)
                and len(node.elts) == 3
                and isinstance(node.elts[1], ast.Constant)
                and node.elts[1].value in ops
            ):
                found.append(f"{relative}:{node.lineno} {ast.unparse(node)}")
    return found


def test_no_tool_builds_an_array_condition_by_hand() -> None:
    assert _hand_built_conditions(Path(fortianalyzer_mcp.__file__).parent) == []
