"""Tests for FortiAnalyzer traffic analysis tools.

Tests validation functions, aggregation logic, and tool behavior
without triggering server initialization.
"""

import asyncio
import os
from collections import Counter

import pytest

os.environ.setdefault("FORTIANALYZER_HOST", "test-faz.local")

import fortianalyzer_mcp.tools.traffic_tools as traffic_tools
from fortianalyzer_mcp.tools.traffic_tools import (
    VALID_ACTIONS,
    _aggregate_port_analysis,
    _aggregate_protocol_summary,
    _aggregate_traffic_profile,
    _build_policy_filter,
    sanitize_filter_value,
    validate_action,
    validate_policy_ids,
)
from fortianalyzer_mcp.utils.validation import ValidationError

# =============================================================================
# Validation: validate_action
# =============================================================================


class TestValidateAction:
    """Tests for action validation."""

    def test_valid_actions(self) -> None:
        """All allowed actions should pass validation."""
        for action in VALID_ACTIONS:
            assert validate_action(action) == action

    def test_none_action(self) -> None:
        """None action should return None."""
        assert validate_action(None) is None

    def test_action_case_insensitive(self) -> None:
        """Action validation should be case-insensitive."""
        assert validate_action("ACCEPT") == "accept"
        assert validate_action("Deny") == "deny"

    def test_action_stripped(self) -> None:
        """Action should be stripped of whitespace."""
        assert validate_action("  accept  ") == "accept"

    def test_invalid_action(self) -> None:
        """Invalid action should raise ValidationError."""
        with pytest.raises(ValidationError, match="Invalid action"):
            validate_action("allow")

    def test_action_with_spaces(self) -> None:
        """Action with embedded spaces should be rejected (injection attempt)."""
        with pytest.raises(ValidationError, match="Invalid action"):
            validate_action("accept or 1==1")

    def test_action_with_operators(self) -> None:
        """Action with filter operators should be rejected."""
        with pytest.raises(ValidationError, match="Invalid action"):
            validate_action("accept==true")

    def test_empty_action(self) -> None:
        """Empty string action should be rejected."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            validate_action("")


# =============================================================================
# Validation: validate_policy_ids
# =============================================================================


class TestValidatePolicyIds:
    """Tests for policy ID validation."""

    def test_valid_single_id(self) -> None:
        """Single valid policy ID."""
        assert validate_policy_ids([1]) == [1]

    def test_valid_multiple_ids(self) -> None:
        """Multiple valid policy IDs."""
        assert validate_policy_ids([1, 5, 10]) == [1, 5, 10]

    def test_empty_list(self) -> None:
        """Empty list should raise ValidationError."""
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_policy_ids([])

    def test_zero_id(self) -> None:
        """Zero policy ID should be rejected."""
        with pytest.raises(ValidationError, match="positive integer"):
            validate_policy_ids([0])

    def test_negative_id(self) -> None:
        """Negative policy ID should be rejected."""
        with pytest.raises(ValidationError, match="positive integer"):
            validate_policy_ids([-1])

    def test_too_many_ids(self) -> None:
        """More than 25 IDs should be rejected."""
        ids = list(range(1, 27))  # 26 IDs
        with pytest.raises(ValidationError, match="Too many policy IDs"):
            validate_policy_ids(ids)

    def test_max_ids_allowed(self) -> None:
        """Exactly 25 IDs should be accepted."""
        ids = list(range(1, 26))  # 25 IDs
        assert validate_policy_ids(ids) == ids

    def test_deduplicates_policy_ids(self) -> None:
        """Duplicate policy IDs should be normalized away."""
        assert validate_policy_ids([1, 5, 1, 10, 5]) == [1, 5, 10]


# =============================================================================
# Validation: sanitize_filter_value
# =============================================================================


class TestSanitizeFilterValue:
    """Tests for filter value sanitization."""

    def test_simple_alphanumeric(self) -> None:
        """Simple alphanumeric values pass through."""
        assert sanitize_filter_value("accept") == "accept"
        assert sanitize_filter_value("10.0.0.1") == "10.0.0.1"
        assert sanitize_filter_value("my-device") == '"my-device"'

    def test_value_with_spaces_gets_quoted(self) -> None:
        """Values with spaces should be quoted."""
        result = sanitize_filter_value("some value")
        assert result == '"some value"'

    def test_value_with_quotes_escaped(self) -> None:
        """Values with double quotes should be escaped."""
        result = sanitize_filter_value('say "hello"')
        assert result == '"say \\"hello\\""'

    def test_value_with_backslash_escaped(self) -> None:
        """Values with backslashes should be escaped."""
        result = sanitize_filter_value("path\\to")
        assert result == '"path\\\\to"'

    def test_injection_attempt_quoted(self) -> None:
        """Filter injection attempts should be safely quoted."""
        result = sanitize_filter_value("accept or 1==1")
        assert result == '"accept or 1==1"'

    def test_empty_value(self) -> None:
        """Empty value should raise ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            sanitize_filter_value("")

    def test_whitespace_only_value(self) -> None:
        """Whitespace-only value should raise ValidationError."""
        with pytest.raises(ValidationError, match="cannot be empty"):
            sanitize_filter_value("   ")

    def test_special_characters_quoted(self) -> None:
        """Values with special characters should be quoted."""
        result = sanitize_filter_value("value;drop")
        assert result.startswith('"')
        assert result.endswith('"')


# =============================================================================
# Filter building
# =============================================================================


class TestBuildPolicyFilter:
    """Tests for filter string construction."""

    def test_policy_only(self) -> None:
        """Filter with only policy ID."""
        assert _build_policy_filter(5) == "policyid==5"

    def test_policy_with_action(self) -> None:
        """Filter with policy ID and action."""
        result = _build_policy_filter(5, "accept")
        assert result == "policyid==5 and action==accept"

    def test_policy_with_none_action(self) -> None:
        """Filter with None action should not include action."""
        assert _build_policy_filter(10, None) == "policyid==10"


# =============================================================================
# Aggregation: traffic profile
# =============================================================================


class TestAggregateTrafficProfile:
    """Tests for traffic profile aggregation."""

    def test_empty_logs(self) -> None:
        """Empty log list should return zero counts."""
        result = _aggregate_traffic_profile([], 10)
        assert result["total_hits"] == 0
        assert result["top_ports"] == []
        assert result["top_services"] == []
        assert result["top_applications"] == []

    def test_basic_aggregation(self) -> None:
        """Basic aggregation of ports, services, apps."""
        logs = [
            {"dstport": 443, "proto": "6", "service": "HTTPS", "app": "SSL"},
            {"dstport": 443, "proto": "6", "service": "HTTPS", "app": "SSL"},
            {"dstport": 80, "proto": "6", "service": "HTTP", "app": "HTTP"},
        ]
        result = _aggregate_traffic_profile(logs, 10)
        assert result["total_hits"] == 3
        assert len(result["top_ports"]) == 2
        # Port 443 should be first (2 hits)
        assert result["top_ports"][0]["port"] == "6/443"
        assert result["top_ports"][0]["hits"] == 2

    def test_top_n_limiting(self) -> None:
        """top_n should limit the number of returned items."""
        logs = [{"dstport": i, "proto": "6", "service": f"svc-{i}"} for i in range(20)]
        result = _aggregate_traffic_profile(logs, 5)
        assert len(result["top_ports"]) == 5
        assert len(result["top_services"]) == 5

    def test_residual_calculation(self) -> None:
        """Residual should be total minus top hits."""
        logs = [
            {"dstport": 443, "proto": "6"},
            {"dstport": 443, "proto": "6"},
            {"dstport": 80, "proto": "6"},
            {"dstport": 22, "proto": "6"},
        ]
        result = _aggregate_traffic_profile(logs, 1)
        # top_n=1 should return port 443 with 2 hits
        assert result["top_ports"][0]["hits"] == 2
        assert result["top_ports_residual"] == 2  # 4 total - 2 top hits

    def test_missing_fields(self) -> None:
        """Logs with missing fields should not crash."""
        logs = [
            {"srcip": "10.0.0.1"},  # No dstport, service, app
            {"dstport": 443, "proto": "6"},  # No service, app
        ]
        result = _aggregate_traffic_profile(logs, 10)
        assert result["total_hits"] == 2
        assert len(result["top_ports"]) == 1
        assert result["top_services"] == []
        assert result["top_applications"] == []


# =============================================================================
# Aggregation: port analysis
# =============================================================================


class TestAggregatePortAnalysis:
    """Tests for port analysis aggregation."""

    def test_empty_logs(self) -> None:
        """Empty logs should return zero counts with is_exact=True."""
        result = _aggregate_port_analysis([])
        assert result["total_hits"] == 0
        assert result["is_exact"] is True
        assert result["ports"] == []
        assert result["protocols"] == []
        assert result["uncovered_port_hits"] == 0

    def test_basic_port_enumeration(self) -> None:
        """Basic port/protocol enumeration."""
        logs = [
            {"dstport": 443, "proto": "6"},
            {"dstport": 80, "proto": "6"},
            {"dstport": 53, "proto": "17"},
        ]
        result = _aggregate_port_analysis(logs)
        assert result["total_hits"] == 3
        assert result["is_exact"] is True
        assert len(result["ports"]) == 3
        assert result["uncovered_port_hits"] == 0

    def test_icmp_handling(self) -> None:
        """ICMP logs should be tracked via service field (FAZ format)."""
        logs = [
            # FAZ encodes ICMP echo as service=PING
            {"proto": "1", "dstport": 0, "service": "PING"},
            {"proto": "1", "dstport": 0, "service": "PING"},
            # FAZ encodes ICMP type/code as service=icmp/T/C
            {"proto": "1", "dstport": 0, "service": "icmp/3/3"},
        ]
        result = _aggregate_port_analysis(logs)
        assert result["total_hits"] == 3
        assert "1" in result["portless_protocols"]
        assert len(result["icmp"]) == 2
        # PING (type=8/code=0) should be most common
        assert result["icmp"][0]["type_code"] == "type=8/code=0"
        assert result["icmp"][0]["hits"] == 2
        # icmp/3/3 → type=3/code=3
        assert result["icmp"][1]["type_code"] == "type=3/code=3"
        assert result["icmp"][1]["hits"] == 1

    def test_portless_protocols(self) -> None:
        """Protocols without ports should be tracked without creating numeric gaps."""
        logs = [
            {"proto": "47", "dstport": 0},  # GRE
            {"proto": "50"},  # ESP, no dstport at all
        ]
        result = _aggregate_port_analysis(logs)
        assert "47" in result["portless_protocols"]
        assert "50" in result["portless_protocols"]
        assert result["uncovered_port_hits"] == 0

    def test_uncovered_port_hits(self) -> None:
        """A complete fetched log set should not report uncovered numeric ports."""
        logs = [
            {"dstport": 443, "proto": "6"},  # Has port
            {"proto": "1"},  # No port
        ]
        result = _aggregate_port_analysis(logs)
        assert result["uncovered_port_hits"] == 0

    def test_partial_aggregation_can_mark_inexact(self) -> None:
        """Incomplete streaming results should be able to mark exactness false."""
        accumulator = traffic_tools.PortAnalysisAccumulator()
        logs = [{"dstport": 443, "proto": "6"}, {"proto": "1", "service": "PING"}]
        accumulator.consume_rows(logs)
        result = accumulator.build_result(is_exact=False)
        assert result["is_exact"] is False
        assert result["uncovered_port_hits"] == len(logs)


# =============================================================================
# Aggregation: protocol summary
# =============================================================================


class TestAggregateProtocolSummary:
    """Tests for protocol summary aggregation."""

    def test_empty_logs(self) -> None:
        """Empty logs should return zero hits."""
        result = _aggregate_protocol_summary([])
        assert result["total_hits"] == 0
        assert result["protocols"] == []

    def test_protocol_name_mapping(self) -> None:
        """Protocol numbers should be mapped to names."""
        logs = [
            {"proto": "6"},
            {"proto": "6"},
            {"proto": "17"},
            {"proto": "1"},
        ]
        result = _aggregate_protocol_summary(logs)
        assert result["total_hits"] == 4
        proto_map = {p["protocol"]: p["hits"] for p in result["protocols"]}
        assert proto_map["TCP"] == 2
        assert proto_map["UDP"] == 1
        assert proto_map["ICMP"] == 1

    def test_unknown_protocol(self) -> None:
        """Unknown protocol numbers should be labeled as other(N)."""
        logs = [{"proto": "99"}]
        result = _aggregate_protocol_summary(logs)
        assert result["protocols"][0]["protocol"] == "other(99)"

    def test_missing_proto_field(self) -> None:
        """Logs without proto field should use 'unknown'."""
        logs = [{"srcip": "10.0.0.1"}]
        result = _aggregate_protocol_summary(logs)
        assert result["protocols"][0]["protocol"] == "other(unknown)"

    def test_protocol_ordering(self) -> None:
        """Protocols should be ordered by hit count descending."""
        logs = [
            {"proto": "17"},
            {"proto": "6"},
            {"proto": "6"},
            {"proto": "6"},
            {"proto": "17"},
        ]
        result = _aggregate_protocol_summary(logs)
        assert result["protocols"][0]["protocol"] == "TCP"
        assert result["protocols"][0]["hits"] == 3
        assert result["protocols"][1]["protocol"] == "UDP"
        assert result["protocols"][1]["hits"] == 2


# =============================================================================
# Exact fetch
# =============================================================================


class TestExactLogFetch:
    """Tests for full exact log retrieval."""

    async def test_fetch_all_pages_until_total_count(self, monkeypatch) -> None:
        """Exact fetch should page until every matched row is retrieved."""

        class FakeClient:
            def __init__(self) -> None:
                self.fetch_calls: list[int] = []

            async def logsearch_start(self, **kwargs):
                return {"tid": 99}

            async def logsearch_fetch(self, adom, tid, limit, offset):
                self.fetch_calls.append(offset)
                if offset == 0:
                    return {
                        "percentage": 100,
                        "total-count": 3,
                        "return-lines": 2,
                        "data": [
                            {"proto": "6", "dstport": 443},
                            {"proto": "17", "dstport": 53},
                        ],
                    }
                if offset == 2:
                    return {
                        "percentage": 100,
                        "total-count": 3,
                        "return-lines": 1,
                        "data": [{"proto": "1", "service": "PING", "dstport": 0}],
                    }
                raise AssertionError(f"Unexpected offset: {offset}")

            async def logsearch_cancel(self, adom, tid):
                return {}

        fake_client = FakeClient()

        async def fake_get_connected_client():
            return fake_client

        monkeypatch.setattr(
            traffic_tools,
            "_get_connected_client",
            fake_get_connected_client,
        )

        collected: list[dict[str, str | int]] = []
        total = await traffic_tools._run_log_fetch_all(
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 01:00:00"},
            filter_str="policyid==42",
            timeout=10,
            consumer=collected.extend,
        )

        assert total == 3
        assert len(collected) == 3
        assert fake_client.fetch_calls == [0, 2]

    async def test_fetch_retry_discards_partial_attempt_rows(self, monkeypatch) -> None:
        """A failed attempt must not leak partial rows into the successful retry."""

        class FakeClient:
            def __init__(self) -> None:
                self.start_calls = 0

            async def logsearch_start(self, **kwargs):
                self.start_calls += 1
                return {"tid": self.start_calls}

            async def logsearch_fetch(self, adom, tid, limit, offset):
                if tid == 1:
                    if offset == 0:
                        return {
                            "percentage": 100,
                            "total-count": 3,
                            "return-lines": 2,
                            "data": [
                                {"proto": "6", "dstport": 443},
                                {"proto": "17", "dstport": 53},
                            ],
                        }
                    if offset == 2:
                        raise OSError("temporary fetch failure")
                if tid == 2:
                    if offset == 0:
                        return {
                            "percentage": 100,
                            "total-count": 3,
                            "return-lines": 2,
                            "data": [
                                {"proto": "6", "dstport": 443},
                                {"proto": "17", "dstport": 53},
                            ],
                        }
                    if offset == 2:
                        return {
                            "percentage": 100,
                            "total-count": 3,
                            "return-lines": 1,
                            "data": [{"proto": "1", "service": "PING", "dstport": 0}],
                        }
                raise AssertionError(f"Unexpected tid/offset: {tid}/{offset}")

            async def logsearch_cancel(self, adom, tid):
                return {}

        fake_client = FakeClient()

        async def fake_get_connected_client():
            return fake_client

        monkeypatch.setattr(
            traffic_tools,
            "_get_connected_client",
            fake_get_connected_client,
        )

        collected: list[dict[str, str | int]] = []
        total = await traffic_tools._run_log_fetch_all(
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 01:00:00"},
            filter_str="policyid==42",
            timeout=10,
            consumer=collected.extend,
        )

        assert total == 3
        assert fake_client.start_calls == 2
        assert len(collected) == 3
        assert collected == [
            {"proto": "6", "dstport": 443},
            {"proto": "17", "dstport": 53},
            {"proto": "1", "service": "PING", "dstport": 0},
        ]

    async def test_resilient_fetch_splits_failed_hour_below_one_hour(self, monkeypatch) -> None:
        """A failed 60-minute slice should recurse to smaller exact ranges."""

        attempted_ranges: list[tuple[str, str]] = []

        async def fake_run_log_fetch_all(**kwargs):
            time_range = kwargs["time_range"]
            attempted_ranges.append((time_range["start"], time_range["end"]))
            if time_range == {
                "start": "2026-04-20 00:00:00",
                "end": "2026-04-20 00:59:59",
            }:
                raise RuntimeError(
                    "Exact fetch failed for filter policyid==42: "
                    "Server error: Invalid tid 123 for fetching result.",
                )
            kwargs["consumer"]([{"proto": "6", "dstport": 443}])
            return 1

        monkeypatch.setattr(
            traffic_tools,
            "_run_log_fetch_all",
            fake_run_log_fetch_all,
        )

        collected: list[dict[str, str | int]] = []
        total = await traffic_tools._run_log_fetch_resilient(
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 00:59:59"},
            filter_str="policyid==42",
            timeout=10,
            consumer=collected.extend,
        )

        assert total == 2
        assert len(collected) == 2
        assert attempted_ranges == [
            ("2026-04-20 00:00:00", "2026-04-20 00:59:59"),
            ("2026-04-20 00:00:00", "2026-04-20 00:29:59"),
            ("2026-04-20 00:30:00", "2026-04-20 00:59:59"),
        ]

    async def test_exact_fetch_uses_bounded_slice_concurrency(self, monkeypatch) -> None:
        """Exact fetch should parallelize top-level slices without exceeding the bound."""

        state = {"current": 0, "max": 0}

        monkeypatch.setattr(
            traffic_tools,
            "_build_exact_time_slices_minutes",
            lambda *_args, **_kwargs: [
                {"start": "2026-04-20 00:00:00", "end": "2026-04-20 00:59:59"},
                {"start": "2026-04-20 01:00:00", "end": "2026-04-20 01:59:59"},
                {"start": "2026-04-20 02:00:00", "end": "2026-04-20 02:59:59"},
                {"start": "2026-04-20 03:00:00", "end": "2026-04-20 03:59:59"},
            ],
        )

        async def fake_run_log_fetch_resilient(**kwargs):
            state["current"] += 1
            state["max"] = max(state["max"], state["current"])
            await asyncio.sleep(0.01)
            kwargs["consumer"]([{"proto": "6", "dstport": 443}])
            state["current"] -= 1
            return 1

        monkeypatch.setattr(
            traffic_tools,
            "_run_log_fetch_resilient",
            fake_run_log_fetch_resilient,
        )

        collected: list[dict[str, str | int]] = []
        total = await traffic_tools._run_log_fetch_exact(
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 03:59:59"},
            filter_str="policyid==42",
            timeout=10,
            slice_minutes=60,
            consumer=collected.extend,
        )

        assert total == 4
        assert len(collected) == 4
        assert state["max"] <= traffic_tools.DEFAULT_PORT_ANALYSIS_SLICE_CONCURRENCY
        assert state["max"] > 1


class TestPortAnalysisCache:
    """Tests for persisted exact slice caching."""

    async def test_cached_slice_reuse_skips_second_fetch(self, monkeypatch, tmp_path) -> None:
        """A completed exact slice should load from disk on the next identical request."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))
        fetch_calls = {"count": 0}

        async def fake_run_log_fetch_all(**kwargs):
            fetch_calls["count"] += 1
            kwargs["consumer"](
                [
                    {"proto": "6", "dstport": 443},
                    {"proto": "1", "service": "PING", "dstport": 0},
                ]
            )
            return 2

        monkeypatch.setattr(traffic_tools, "_run_log_fetch_all", fake_run_log_fetch_all)

        first = await traffic_tools._collect_port_analysis_slice_accumulator(
            policy_id=42,
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 00:59:59"},
            action=None,
            filter_str="policyid==42",
            timeout=10,
        )
        second = await traffic_tools._collect_port_analysis_slice_accumulator(
            policy_id=42,
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 00:59:59"},
            action=None,
            filter_str="policyid==42",
            timeout=10,
        )

        assert fetch_calls["count"] == 1
        assert first.total_hits == 2
        assert second.total_hits == 2
        assert second.port_counter == Counter({"6/443": 1})

    async def test_parent_range_is_cached_after_split_merge(self, monkeypatch, tmp_path) -> None:
        """A split exact run should persist the merged parent result for direct reuse."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))
        attempted_ranges: list[tuple[str, str]] = []

        async def fake_run_log_fetch_all(**kwargs):
            time_range = kwargs["time_range"]
            attempted_ranges.append((time_range["start"], time_range["end"]))
            if time_range == {
                "start": "2026-04-20 00:00:00",
                "end": "2026-04-20 00:59:59",
            }:
                raise RuntimeError(
                    "Exact fetch failed for filter policyid==42: "
                    "Server error: Invalid tid 123 for fetching result.",
                )
            kwargs["consumer"]([{"proto": "6", "dstport": 443}])
            return 1

        monkeypatch.setattr(traffic_tools, "_run_log_fetch_all", fake_run_log_fetch_all)

        first = await traffic_tools._run_cached_port_analysis_exact(
            policy_id=42,
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 00:59:59"},
            action=None,
            filter_str="policyid==42",
            timeout=10,
            slice_minutes=60,
        )

        async def fail_if_called(**kwargs):
            raise AssertionError("merged parent result should come from cache")

        monkeypatch.setattr(traffic_tools, "_run_log_fetch_all", fail_if_called)

        second = await traffic_tools._run_cached_port_analysis_exact(
            policy_id=42,
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 00:59:59"},
            action=None,
            filter_str="policyid==42",
            timeout=10,
            slice_minutes=60,
        )

        assert first.total_hits == 2
        assert second.total_hits == 2
        assert attempted_ranges == [
            ("2026-04-20 00:00:00", "2026-04-20 00:59:59"),
            ("2026-04-20 00:00:00", "2026-04-20 00:29:59"),
            ("2026-04-20 00:30:00", "2026-04-20 00:59:59"),
        ]

    def test_minute_slices_align_to_stable_boundaries(self) -> None:
        """Interior exact slices should align to stable buckets for cache reuse."""
        slices = traffic_tools._build_exact_time_slices_minutes(
            {"start": "2026-04-20 00:15:00", "end": "2026-04-20 03:14:59"},
            60,
        )

        assert slices == [
            {"start": "2026-04-20 00:15:00", "end": "2026-04-20 00:59:59"},
            {"start": "2026-04-20 01:00:00", "end": "2026-04-20 01:59:59"},
            {"start": "2026-04-20 02:00:00", "end": "2026-04-20 02:59:59"},
            {"start": "2026-04-20 03:00:00", "end": "2026-04-20 03:14:59"},
        ]

    async def test_shifted_relative_windows_reuse_aligned_slice_cache(
        self, monkeypatch, tmp_path
    ) -> None:
        """Shifted windows should reuse overlapping aligned slices instead of refetching all."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))
        fetched_ranges: list[tuple[str, str]] = []

        async def fake_run_log_fetch_all(**kwargs):
            time_range = kwargs["time_range"]
            fetched_ranges.append((time_range["start"], time_range["end"]))
            kwargs["consumer"]([{"proto": "6", "dstport": 443}])
            return 1

        monkeypatch.setattr(traffic_tools, "_run_log_fetch_all", fake_run_log_fetch_all)

        first = await traffic_tools._run_cached_port_analysis_exact(
            policy_id=42,
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            time_range={"start": "2026-04-20 00:15:00", "end": "2026-04-20 03:14:59"},
            action=None,
            filter_str="policyid==42",
            timeout=10,
            slice_minutes=60,
        )
        second = await traffic_tools._run_cached_port_analysis_exact(
            policy_id=42,
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            time_range={"start": "2026-04-20 01:20:00", "end": "2026-04-20 04:19:59"},
            action=None,
            filter_str="policyid==42",
            timeout=10,
            slice_minutes=60,
        )

        assert first.total_hits == 4
        assert second.total_hits == 4
        assert fetched_ranges == [
            ("2026-04-20 00:15:00", "2026-04-20 00:59:59"),
            ("2026-04-20 01:00:00", "2026-04-20 01:59:59"),
            ("2026-04-20 02:00:00", "2026-04-20 02:59:59"),
            ("2026-04-20 03:00:00", "2026-04-20 03:14:59"),
            ("2026-04-20 01:20:00", "2026-04-20 01:59:59"),
            ("2026-04-20 03:00:00", "2026-04-20 03:59:59"),
            ("2026-04-20 04:00:00", "2026-04-20 04:19:59"),
        ]

    async def test_parent_slice_reuses_cached_descendants_before_refetch(
        self, monkeypatch, tmp_path
    ) -> None:
        """A rerun should rebuild a missing parent slice from cached children immediately."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))

        left = traffic_tools.PortAnalysisAccumulator()
        left.consume_rows([{"proto": "6", "dstport": 443}])
        right = traffic_tools.PortAnalysisAccumulator()
        right.consume_rows([{"proto": "17", "dstport": 53}])

        traffic_tools._store_cached_port_analysis_accumulator(
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            policy_id=42,
            action=None,
            time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 00:29:59"},
            accumulator=left,
        )
        traffic_tools._store_cached_port_analysis_accumulator(
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            policy_id=42,
            action=None,
            time_range={"start": "2026-04-20 00:30:00", "end": "2026-04-20 00:59:59"},
            accumulator=right,
        )

        async def fail_if_called(**kwargs):
            raise AssertionError("parent slice should be rebuilt from cached descendants")

        monkeypatch.setattr(traffic_tools, "_run_log_fetch_all", fail_if_called)

        rebuilt = await traffic_tools._collect_port_analysis_slice_accumulator(
            policy_id=42,
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 00:59:59"},
            action=None,
            filter_str="policyid==42",
            timeout=10,
            min_split_minutes=5,
        )

        assert rebuilt.total_hits == 2
        assert rebuilt.port_counter == Counter({"6/443": 1, "17/53": 1})
        assert traffic_tools._has_cached_port_analysis_accumulator(
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            policy_id=42,
            action=None,
            time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 00:59:59"},
        )

    async def test_wrapped_timeout_runtime_error_still_splits(self, monkeypatch, tmp_path) -> None:
        """A wrapped timeout message should still trigger recursive exact splitting."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))
        attempted_ranges: list[tuple[str, str]] = []

        async def fake_run_log_fetch_all(**kwargs):
            time_range = kwargs["time_range"]
            attempted_ranges.append((time_range["start"], time_range["end"]))
            if time_range == {
                "start": "2026-04-20 00:00:00",
                "end": "2026-04-20 00:59:59",
            }:
                raise RuntimeError(
                    "Exact fetch failed for filter policyid==42: "
                    "Exact fetch paging timed out after 120s for filter policyid==42",
                )
            kwargs["consumer"]([{"proto": "6", "dstport": 443}])
            return 1

        monkeypatch.setattr(traffic_tools, "_run_log_fetch_all", fake_run_log_fetch_all)

        accumulator = await traffic_tools._collect_port_analysis_slice_accumulator(
            policy_id=42,
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 00:59:59"},
            action=None,
            filter_str="policyid==42",
            timeout=10,
        )

        assert accumulator.total_hits == 2
        assert attempted_ranges == [
            ("2026-04-20 00:00:00", "2026-04-20 00:59:59"),
            ("2026-04-20 00:00:00", "2026-04-20 00:29:59"),
            ("2026-04-20 00:30:00", "2026-04-20 00:59:59"),
        ]


class TestPortAnalysisEstimate:
    """Tests for policy-hit estimates used by the exact guard."""

    async def test_estimate_pages_until_requested_policy_is_found(self, monkeypatch) -> None:
        """The estimator should page until it finds all requested policies."""

        class FakeClient:
            def __init__(self) -> None:
                self.offsets: list[int] = []
                self.current_offset = 0

            async def fortiview_run(self, **kwargs):
                self.current_offset = int(kwargs["offset"])
                self.offsets.append(self.current_offset)
                return {"tid": self.current_offset + 1}

            async def fortiview_fetch(self, **kwargs):
                if self.current_offset == 0:
                    return {
                        "percentage": 100,
                        "data": [
                            {"agg_policyid": "42", "policytype": "local-in-policy", "counts": "900"},
                            *[
                                {
                                    "agg_policyid": str(policy_id),
                                    "policytype": "policy",
                                    "counts": "5",
                                }
                                for policy_id in range(1000, 1099)
                            ],
                        ],
                    }
                if self.current_offset == 100:
                    return {
                        "percentage": 100,
                        "data": [
                            {"agg_policyid": "42", "policytype": "policy", "counts": "7"},
                        ],
                    }
                raise AssertionError(f"Unexpected offset: {self.current_offset}")

        fake_client = FakeClient()

        async def fake_get_connected_client():
            return fake_client

        monkeypatch.setattr(traffic_tools, "_get_connected_client", fake_get_connected_client)

        estimate = await traffic_tools._estimate_port_analysis_hits(
            adom="root",
            device_filter=[{"devname": "MTLHQIF001"}],
            full_time_range={"start": "2026-04-01 00:00:00", "end": "2026-04-08 00:00:00"},
            policy_ids=[42],
            action=None,
        )

        assert estimate.complete is True
        assert estimate.hits_by_policy == {42: 7}
        assert fake_client.offsets == [0, 100]

    async def test_estimate_marks_missing_policy_incomplete(self, monkeypatch) -> None:
        """Missing requested policies should keep the estimate incomplete."""

        class FakeClient:
            async def fortiview_run(self, **kwargs):
                return {"tid": 1}

            async def fortiview_fetch(self, **kwargs):
                return {
                    "percentage": 100,
                    "data": [{"agg_policyid": "7", "policytype": "policy", "counts": "5"}],
                }

        async def fake_get_connected_client():
            return FakeClient()

        monkeypatch.setattr(traffic_tools, "_get_connected_client", fake_get_connected_client)

        estimate = await traffic_tools._estimate_port_analysis_hits(
            adom="root",
            device_filter=[{"devname": "MTLHQIF001"}],
            full_time_range={"start": "2026-04-01 00:00:00", "end": "2026-04-08 00:00:00"},
            policy_ids=[42],
            action=None,
        )

        assert estimate.complete is False
        assert estimate.hits_by_policy == {}


class TestPortAnalysisPlanning:
    """Tests for the planned exact-execution model."""

    def test_plan_allows_small_complete_estimate(self) -> None:
        """Small complete estimates should produce an executable plan."""
        estimate = traffic_tools.PortAnalysisEstimate(hits_by_policy={42: 1200}, complete=True)
        plan = traffic_tools._plan_port_analysis_run(
            policy_ids=[42],
            full_time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 12:00:00"},
            estimate=estimate,
        )
        error = traffic_tools._port_analysis_guard_error(
            policy_ids=[42],
            full_time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 12:00:00"},
            plan=plan,
        )
        assert plan.should_execute is True
        assert plan.policy_slice_minutes[42] >= 60
        assert error is None

    def test_plan_allows_medium_request_above_old_hit_cutoff(self) -> None:
        """A medium request should execute when the slice/page plan still fits."""
        estimate = traffic_tools.PortAnalysisEstimate(hits_by_policy={42: 8000}, complete=True)
        plan = traffic_tools._plan_port_analysis_run(
            policy_ids=[42],
            full_time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-21 00:00:00"},
            estimate=estimate,
        )
        assert plan.should_execute is True
        assert plan.policy_slice_minutes[42] == 180
        assert plan.estimated_total_slices == 9
        assert plan.estimated_total_pages == 18

    def test_plan_allows_dense_single_policy_day_window(self) -> None:
        """A dense one-day request for one policy should stay eligible for exact execution."""
        estimate = traffic_tools.PortAnalysisEstimate(hits_by_policy={2: 43993}, complete=True)
        plan = traffic_tools._plan_port_analysis_run(
            policy_ids=[2],
            full_time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-21 00:00:00"},
            estimate=estimate,
        )

        assert plan.should_execute is True
        assert plan.policy_slice_minutes[2] == 60
        assert plan.estimated_total_slices == 25
        assert plan.estimated_total_pages == 100

    def test_plan_allows_live_sized_single_policy_day_window(self) -> None:
        """The measured one-day live policy shape should stay within the middle-ground plan."""
        estimate = traffic_tools.PortAnalysisEstimate(hits_by_policy={2: 53808}, complete=True)
        plan = traffic_tools._plan_port_analysis_run(
            policy_ids=[2],
            full_time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-21 00:00:00"},
            estimate=estimate,
        )

        assert plan.should_execute is True
        assert plan.policy_slice_minutes[2] == 60
        assert plan.estimated_total_slices == 25
        assert plan.estimated_total_pages == 125

    def test_plan_rejects_large_complete_estimate(self) -> None:
        """Large complete estimates should fail when the planned work is too large."""
        estimate = traffic_tools.PortAnalysisEstimate(
            hits_by_policy={2: 120000, 7: 40000},
            complete=True,
        )
        plan = traffic_tools._plan_port_analysis_run(
            policy_ids=[2, 7],
            full_time_range={"start": "2026-04-01 00:00:00", "end": "2026-04-30 23:59:59"},
            estimate=estimate,
        )
        error = traffic_tools._port_analysis_guard_error(
            policy_ids=[2, 7],
            full_time_range={"start": "2026-04-01 00:00:00", "end": "2026-04-30 23:59:59"},
            plan=plan,
        )
        assert plan.should_execute is False
        assert error is not None
        assert "planned" in error
        assert "Split policies into separate calls" in error

    def test_plan_rejects_incomplete_large_window(self) -> None:
        """Incomplete estimates should fail closed when the heuristic plan is too large."""
        estimate = traffic_tools.PortAnalysisEstimate(hits_by_policy={2: 400}, complete=False)
        plan = traffic_tools._plan_port_analysis_run(
            policy_ids=[2, 7, 8],
            full_time_range={"start": "2026-04-01 00:00:00", "end": "2026-04-30 23:59:59"},
            estimate=estimate,
        )
        error = traffic_tools._port_analysis_guard_error(
            policy_ids=[2, 7, 8],
            full_time_range={"start": "2026-04-01 00:00:00", "end": "2026-04-30 23:59:59"},
            plan=plan,
        )
        assert plan.should_execute is False
        assert "missing estimate for policies 7, 8" in error
        assert "planned" in error

    def test_high_risk_shape_skips_estimate(self) -> None:
        """Clearly oversized request shapes should skip the FortiView estimator."""
        assert (
            traffic_tools._should_skip_port_analysis_estimate(
                policy_ids=[2, 7, 8],
                full_time_range={"start": "2026-04-01 00:00:00", "end": "2026-04-30 23:59:59"},
            )
            is True
        )
        assert (
            traffic_tools._should_skip_port_analysis_estimate(
                policy_ids=[2, 7],
                full_time_range={"start": "2026-04-01 00:00:00", "end": "2026-04-08 00:00:00"},
            )
            is False
        )
        assert (
            traffic_tools._should_skip_port_analysis_estimate(
                policy_ids=[42],
                full_time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-20 12:00:00"},
            )
            is False
        )


# =============================================================================
# Public tool behavior
# =============================================================================


class TestPolicyTrafficProfileTool:
    """Tests for sampled policy traffic profiles."""

    async def test_zero_hit_policy_returns_empty_profile(self, monkeypatch) -> None:
        """Zero-hit policies should return a clean empty structure."""

        async def fake_run_log_count_exact(**kwargs):
            return 0

        monkeypatch.setattr(traffic_tools, "_run_log_count_exact", fake_run_log_count_exact)

        result = await traffic_tools.get_policy_traffic_profile(
            policy_ids=[42],
            adom="root",
            time_range="24-hour",
        )

        assert result["status"] == "success"
        assert result["results"] == [
            {
                "policy_id": 42,
                "total_hits": 0,
                "top_ports": [],
                "top_ports_residual": 0,
                "top_services": [],
                "top_services_residual": 0,
                "top_applications": [],
                "top_applications_residual": 0,
            }
        ]

    async def test_profile_uses_discovery_plus_exact_recounts(self, monkeypatch) -> None:
        """Sampled profiles should recount discovered candidates over the full window."""

        async def fake_run_log_count_exact(**kwargs):
            filter_str = kwargs.get("filter_str") or ""
            if filter_str == "policyid==42":
                return 10
            if filter_str == "policyid==42 and proto==6 and dstport==443":
                return 6
            if filter_str == "policyid==42 and proto==17 and dstport==53":
                return 2
            if filter_str == "policyid==42 and service==HTTPS":
                return 6
            if filter_str == "policyid==42 and service==DNS":
                return 2
            if filter_str == "policyid==42 and app==SSL":
                return 6
            if filter_str == "policyid==42 and app==DNS":
                return 2
            raise AssertionError(f"Unexpected filter in test: {filter_str}")

        async def fake_discover_policy_candidates(**kwargs):
            return {
                "port_pair": Counter({"6/443": 10, "17/53": 4}),
                "service": Counter({"HTTPS": 10, "DNS": 4}),
                "app": Counter({"SSL": 10, "DNS": 4}),
            }, {"errors": []}

        monkeypatch.setattr(traffic_tools, "_run_log_count_exact", fake_run_log_count_exact)
        monkeypatch.setattr(
            traffic_tools,
            "_discover_policy_candidates",
            fake_discover_policy_candidates,
        )

        result = await traffic_tools.get_policy_traffic_profile(
            policy_ids=[42],
            adom="root",
            time_range="7-day",
        )

        assert result["status"] == "success"
        policy = result["results"][0]
        assert policy["total_hits"] == 10
        assert policy["top_ports"] == [
            {"port": "6/443", "hits": 6},
            {"port": "17/53", "hits": 2},
        ]
        assert policy["top_ports_residual"] == 2
        assert policy["top_services_residual"] == 2
        assert policy["top_applications_residual"] == 2

    async def test_partial_policy_failures_are_reported_inline(self, monkeypatch) -> None:
        """Per-policy failures should not fail the entire response."""

        async def fake_builder(*, policy_id, **kwargs):
            if policy_id == 2:
                raise RuntimeError("boom")
            return {"policy_id": policy_id, "total_hits": policy_id, "top_ports": []}

        monkeypatch.setattr(
            traffic_tools,
            "_build_policy_traffic_profile_result",
            fake_builder,
        )

        result = await traffic_tools.get_policy_traffic_profile(
            policy_ids=[1, 2],
            adom="root",
        )

        assert result["status"] == "success"
        assert result["results"][0]["policy_id"] == 1
        assert result["results"][1] == {"policy_id": 2, "error": "boom"}

    async def test_policy_work_is_semaphore_bounded(self, monkeypatch) -> None:
        """No more than five policies should run concurrently."""
        state = {"current": 0, "max": 0}

        async def fake_builder(*, policy_id, **kwargs):
            state["current"] += 1
            state["max"] = max(state["max"], state["current"])
            await asyncio.sleep(0.01)
            state["current"] -= 1
            return {"policy_id": policy_id, "total_hits": policy_id, "top_ports": []}

        monkeypatch.setattr(
            traffic_tools,
            "_build_policy_traffic_profile_result",
            fake_builder,
        )

        result = await traffic_tools.get_policy_traffic_profile(
            policy_ids=[1, 2, 3, 4, 5, 6, 7],
            adom="root",
        )

        assert result["status"] == "success"
        assert state["max"] <= 5
        assert state["max"] > 1


class TestPolicyPortAnalysisTool:
    """Tests for exact policy port analysis."""

    async def test_exact_analysis_closes_numeric_port_coverage(
        self,
        monkeypatch,
        tmp_path,
    ) -> None:
        """Exact analysis should mark the result exact after a full log fetch."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))

        logs = (
            [{"proto": "6", "dstport": 443}] * 6
            + [{"proto": "6", "dstport": 8443}] * 4
            + [{"proto": "1", "dstport": 0, "service": "PING"}] * 2
            + [{"proto": "1", "dstport": 0, "service": "icmp/3/3"}]
        )

        async def fake_run_cached_port_analysis_exact(**kwargs):
            assert kwargs["filter_str"] == "policyid==42"
            accumulator = traffic_tools.PortAnalysisAccumulator()
            accumulator.consume_rows(logs)
            return accumulator

        async def fake_estimate_port_analysis_hits(**kwargs):
            return traffic_tools.PortAnalysisEstimate(hits_by_policy={42: len(logs)}, complete=True)

        monkeypatch.setattr(
            traffic_tools,
            "_run_cached_port_analysis_exact",
            fake_run_cached_port_analysis_exact,
        )
        monkeypatch.setattr(
            traffic_tools,
            "_estimate_port_analysis_hits",
            fake_estimate_port_analysis_hits,
        )

        result = await traffic_tools.get_policy_port_analysis(
            policy_ids=[42],
            adom="root",
            time_range="1-day",
        )

        assert result["status"] == "success"
        policy = result["results"][0]
        assert policy["is_exact"] is True
        assert policy["uncovered_port_hits"] == 0
        assert policy["ports"] == [
            {"port": "6/443", "hits": 6},
            {"port": "6/8443", "hits": 4},
        ]
        assert policy["protocols"] == [
            {"protocol": "6", "hits": 10},
            {"protocol": "1", "hits": 3},
        ]
        assert policy["portless_protocols"] == ["1"]
        assert policy["icmp"] == [
            {"type_code": "type=8/code=0", "hits": 2},
            {"type_code": "type=3/code=3", "hits": 1},
        ]

    async def test_uncovered_hits_track_numeric_port_gap_not_portless_traffic(
        self,
        monkeypatch,
        tmp_path,
    ) -> None:
        """Portless traffic should not make a complete exact fetch report a numeric gap."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))

        logs = (
            [{"proto": "6", "dstport": 443}] * 6
            + [{"proto": "6", "dstport": 8443}] * 6
            + [{"proto": "1", "dstport": 0, "service": "PING"}]
        )

        async def fake_run_cached_port_analysis_exact(**kwargs):
            assert kwargs["filter_str"] == "policyid==42"
            accumulator = traffic_tools.PortAnalysisAccumulator()
            accumulator.consume_rows(logs)
            return accumulator

        async def fake_estimate_port_analysis_hits(**kwargs):
            return traffic_tools.PortAnalysisEstimate(hits_by_policy={42: len(logs)}, complete=True)

        monkeypatch.setattr(
            traffic_tools,
            "_run_cached_port_analysis_exact",
            fake_run_cached_port_analysis_exact,
        )
        monkeypatch.setattr(
            traffic_tools,
            "_estimate_port_analysis_hits",
            fake_estimate_port_analysis_hits,
        )

        result = await traffic_tools.get_policy_port_analysis(
            policy_ids=[42],
            adom="root",
            time_range="1-day",
        )

        policy = result["results"][0]
        assert policy["is_exact"] is True
        assert policy["uncovered_port_hits"] == 0
        assert policy["icmp"] == [{"type_code": "type=8/code=0", "hits": 1}]

    async def test_tool_fails_closed_before_exact_fetch(self, monkeypatch, tmp_path) -> None:
        """Oversized requests should return a guard error before exact execution starts."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))

        async def fake_estimate_port_analysis_hits(**kwargs):
            return traffic_tools.PortAnalysisEstimate(
                hits_by_policy={2: 120000, 7: 40000},
                complete=True,
            )

        async def fail_if_called(**kwargs):
            raise AssertionError("exact fetch should not run when the guard fails")

        monkeypatch.setattr(
            traffic_tools,
            "_estimate_port_analysis_hits",
            fake_estimate_port_analysis_hits,
        )
        monkeypatch.setattr(traffic_tools, "_run_cached_port_analysis_exact", fail_if_called)

        result = await traffic_tools.get_policy_port_analysis(
            policy_ids=[2, 7],
            adom="root",
            time_range="30-day",
        )

        assert result["status"] == "error"
        assert "Split policies into separate calls" in result["message"]

    async def test_medium_planned_request_executes_with_auto_slicing(
        self,
        monkeypatch,
        tmp_path,
    ) -> None:
        """A medium planned request should execute instead of failing on raw hit count."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))

        expected_slice_minutes = 180

        async def fake_estimate_port_analysis_hits(**kwargs):
            return traffic_tools.PortAnalysisEstimate(hits_by_policy={42: 8000}, complete=True)

        async def fake_run_cached_port_analysis_exact(**kwargs):
            assert kwargs["slice_minutes"] == expected_slice_minutes
            accumulator = traffic_tools.PortAnalysisAccumulator()
            accumulator.consume_rows([{"proto": "6", "dstport": 443}] * 3)
            return accumulator

        monkeypatch.setattr(
            traffic_tools,
            "_estimate_port_analysis_hits",
            fake_estimate_port_analysis_hits,
        )
        monkeypatch.setattr(
            traffic_tools,
            "_run_cached_port_analysis_exact",
            fake_run_cached_port_analysis_exact,
        )

        result = await traffic_tools.get_policy_port_analysis(
            policy_ids=[42],
            adom="root",
            time_range="1-day",
        )

        assert result["status"] == "success"
        policy = result["results"][0]
        assert policy["total_hits"] == 3

    async def test_high_risk_request_fails_before_estimation(self, monkeypatch, tmp_path) -> None:
        """Large multi-policy windows should fail before running the estimator."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))

        async def fail_if_called(**kwargs):
            raise AssertionError("estimator should be skipped for high-risk request shapes")

        monkeypatch.setattr(
            traffic_tools,
            "_estimate_port_analysis_hits",
            fail_if_called,
        )

        result = await traffic_tools.get_policy_port_analysis(
            policy_ids=[2, 7, 8],
            adom="root",
            time_range="30-day",
        )

        assert result["status"] == "error"
        assert "FortiView estimate unavailable" in result["message"]

    async def test_cached_full_window_bypasses_sync_guard(self, monkeypatch, tmp_path) -> None:
        """A previously cached exact window should stay usable even if the planner would reject it."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))

        accumulator = traffic_tools.PortAnalysisAccumulator()
        accumulator.consume_rows([{"proto": "6", "dstport": 443}] * 2)
        full_time_range = {"start": "2026-04-01 00:00:00", "end": "2026-04-30 23:59:59"}
        traffic_tools._store_cached_port_analysis_accumulator(
            adom="root",
            device_filter=[{"devid": "All_FortiGate"}],
            policy_id=42,
            action=None,
            time_range=full_time_range,
            accumulator=accumulator,
        )

        async def fail_if_called(**kwargs):
            raise AssertionError("planner should not estimate or refetch when cache is complete")

        monkeypatch.setattr(traffic_tools, "_estimate_port_analysis_hits", fail_if_called)
        monkeypatch.setattr(traffic_tools, "_run_log_fetch_all", fail_if_called)
        monkeypatch.setattr(
            traffic_tools,
            "_parse_time_range",
            lambda _time_range: full_time_range,
        )

        result = await traffic_tools.get_policy_port_analysis(
            policy_ids=[42],
            adom="root",
            time_range="30-day",
        )

        assert result["status"] == "success"
        assert result["results"][0]["total_hits"] == 2
        assert result["results"][0]["is_exact"] is True


class TestPolicyPortAnalysisJobs:
    """Tests for fork-only background exact-analysis jobs."""

    async def test_background_job_start_and_poll(self, monkeypatch, tmp_path) -> None:
        """A started background job should persist and expose its completed result."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))

        async def fake_estimate_port_analysis_hits(**kwargs):
            policy_id = kwargs["policy_ids"][0]
            return traffic_tools.PortAnalysisEstimate(hits_by_policy={policy_id: 2}, complete=True)

        async def fake_build_policy_port_analysis_result(**kwargs):
            return {
                "policy_id": kwargs["policy_id"],
                "total_hits": 2,
                "is_exact": True,
                "ports": [{"port": "6/443", "hits": 2}],
                "protocols": [{"protocol": "6", "hits": 2}],
                "portless_protocols": [],
                "uncovered_port_hits": 0,
                "icmp": [],
            }

        monkeypatch.setattr(
            traffic_tools,
            "_estimate_port_analysis_hits",
            fake_estimate_port_analysis_hits,
        )
        monkeypatch.setattr(
            traffic_tools,
            "_build_policy_port_analysis_result",
            fake_build_policy_port_analysis_result,
        )

        started = await traffic_tools.start_policy_port_analysis_job(
            policy_ids=[42],
            adom="root",
            time_range="1-day",
        )

        assert started["status"] == "success"
        job_id = started["job_id"]
        task = traffic_tools._PORT_ANALYSIS_JOB_TASKS[job_id]
        await task

        polled = await traffic_tools.get_policy_port_analysis_job(job_id)
        assert polled["status"] == "success"
        job = polled["job"]
        assert job["status"] == "completed"
        assert job["estimate"] == {"hits_by_policy": {"42": 2}, "complete": True}
        assert job["result"]["status"] == "success"
        assert job["result"]["results"][0]["policy_id"] == 42

    async def test_stale_running_job_is_marked_interrupted(self, monkeypatch, tmp_path) -> None:
        """Polling a persisted running job with no active task should mark it interrupted."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))
        job_state = traffic_tools._build_port_analysis_job_state(
            job_id="job-123",
            adom="root",
            device=None,
            device_filter=[{"devid": "All_FortiGate"}],
            policy_ids=[42],
            time_range="1-day",
            full_time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-21 00:00:00"},
            action=None,
            estimate=traffic_tools.PortAnalysisEstimate(),
        )
        job_state["status"] = "running"
        traffic_tools._store_port_analysis_job_state(job_state)
        traffic_tools._PORT_ANALYSIS_JOB_TASKS.pop("job-123", None)

        result = await traffic_tools.get_policy_port_analysis_job("job-123")

        assert result["status"] == "success"
        assert result["job"]["status"] == "interrupted"
        assert "no longer active" in result["job"]["error"].lower()

    def test_mark_stale_jobs_interrupted(self, monkeypatch, tmp_path) -> None:
        """Persisted queued/running jobs should be marked interrupted on restart."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))
        queued = traffic_tools._build_port_analysis_job_state(
            job_id="queued-job",
            adom="root",
            device=None,
            device_filter=[{"devid": "All_FortiGate"}],
            policy_ids=[42],
            time_range="1-day",
            full_time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-21 00:00:00"},
            action=None,
            estimate=traffic_tools.PortAnalysisEstimate(),
        )
        running = traffic_tools._build_port_analysis_job_state(
            job_id="running-job",
            adom="root",
            device=None,
            device_filter=[{"devid": "All_FortiGate"}],
            policy_ids=[43],
            time_range="1-day",
            full_time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-21 00:00:00"},
            action=None,
            estimate=traffic_tools.PortAnalysisEstimate(),
        )
        running["status"] = "running"
        completed = traffic_tools._build_port_analysis_job_state(
            job_id="completed-job",
            adom="root",
            device=None,
            device_filter=[{"devid": "All_FortiGate"}],
            policy_ids=[44],
            time_range="1-day",
            full_time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-21 00:00:00"},
            action=None,
            estimate=traffic_tools.PortAnalysisEstimate(),
        )
        completed["status"] = "completed"

        traffic_tools._store_port_analysis_job_state(queued)
        traffic_tools._store_port_analysis_job_state(running)
        traffic_tools._store_port_analysis_job_state(completed)

        interrupted = traffic_tools.mark_stale_port_analysis_jobs_interrupted("server restarted")

        assert interrupted == 2
        assert traffic_tools._load_port_analysis_job_state("queued-job")["status"] == "interrupted"
        assert traffic_tools._load_port_analysis_job_state("running-job")["status"] == "interrupted"
        assert traffic_tools._load_port_analysis_job_state("completed-job")["status"] == "completed"

    async def test_shutdown_jobs_cancels_tasks(self, monkeypatch, tmp_path) -> None:
        """In-process background jobs should be cancelled and persisted as interrupted."""
        monkeypatch.setenv("FAZ_TRAFFIC_CACHE_DIR", str(tmp_path))
        job_state = traffic_tools._build_port_analysis_job_state(
            job_id="live-job",
            adom="root",
            device=None,
            device_filter=[{"devid": "All_FortiGate"}],
            policy_ids=[42],
            time_range="1-day",
            full_time_range={"start": "2026-04-20 00:00:00", "end": "2026-04-21 00:00:00"},
            action=None,
            estimate=traffic_tools.PortAnalysisEstimate(),
        )
        job_state["status"] = "running"
        traffic_tools._store_port_analysis_job_state(job_state)

        async def sleeper() -> None:
            await asyncio.sleep(60)

        task = asyncio.create_task(sleeper())
        traffic_tools._PORT_ANALYSIS_JOB_TASKS["live-job"] = task

        interrupted = await traffic_tools.shutdown_port_analysis_jobs("server stopped")

        assert interrupted == 1
        assert traffic_tools._PORT_ANALYSIS_JOB_TASKS == {}
        assert task.cancelled() or task.done()
        persisted = traffic_tools._load_port_analysis_job_state("live-job")
        assert persisted["status"] == "interrupted"
        assert persisted["error"] == "server stopped"


class TestPolicyProtocolSummaryTool:
    """Tests for protocol summary behavior."""

    async def test_protocol_summary_uses_exact_protocol_counts(self, monkeypatch) -> None:
        """Protocol summaries should use tracked exact buckets plus residual numeric hits."""

        async def fake_run_log_count_exact(**kwargs):
            filter_str = kwargs.get("filter_str") or ""
            if filter_str == "policyid==42":
                return 5
            if filter_str.startswith("policyid==42 and proto==") and filter_str.count(" and ") == 1:
                protocol = filter_str.rsplit("==", maxsplit=1)[1]
                return {"6": 2, "17": 1, "1": 1}.get(protocol, 0)
            raise AssertionError(f"Unexpected filter in test: {filter_str}")

        async def fake_discover_protocol_candidates(**kwargs):
            assert kwargs["policy_filter"] == "policyid==42"
            return Counter({"6": 5, "17": 3, "1": 2, "200": 1})

        monkeypatch.setattr(traffic_tools, "_run_log_count_exact", fake_run_log_count_exact)
        monkeypatch.setattr(
            traffic_tools,
            "_discover_protocol_candidates",
            fake_discover_protocol_candidates,
        )

        result = await traffic_tools.get_policy_protocol_summary(
            policy_ids=[42],
            adom="root",
            time_range="24-hour",
        )

        assert result["status"] == "success"
        assert result["results"][0] == {
            "policy_id": 42,
            "total_hits": 5,
            "protocols": [
                {"protocol": "TCP", "hits": 2},
                {"protocol": "ICMP", "hits": 1},
                {"protocol": "UDP", "hits": 1},
                {"protocol": "other", "hits": 1},
            ],
        }
