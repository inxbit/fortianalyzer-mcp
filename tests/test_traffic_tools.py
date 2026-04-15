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
        """Protocols without ports (GRE, ESP) should be tracked."""
        logs = [
            {"proto": "47", "dstport": 0},  # GRE
            {"proto": "50"},  # ESP, no dstport at all
        ]
        result = _aggregate_port_analysis(logs)
        assert "47" in result["portless_protocols"]
        assert "50" in result["portless_protocols"]
        assert result["uncovered_port_hits"] == 2

    def test_uncovered_port_hits(self) -> None:
        """Logs without destination ports count as uncovered."""
        logs = [
            {"dstport": 443, "proto": "6"},  # Has port
            {"proto": "1"},  # No port
        ]
        result = _aggregate_port_analysis(logs)
        assert result["uncovered_port_hits"] == 1


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

    async def test_exact_analysis_closes_numeric_port_coverage(self, monkeypatch) -> None:
        """Exact analysis should mark the result exact when all numeric ports close."""

        async def fake_run_log_count_exact(**kwargs):
            filter_str = kwargs.get("filter_str") or ""
            mapping = {
                "policyid==42": 13,
                "policyid==42 and proto>=0 and proto<=255": 13,
                "policyid==42 and dstport>=1 and dstport<=65535": 10,
                "policyid==42 and proto==6 and dstport>=1 and dstport<=65535": 10,
                "policyid==42 and proto==1 and dstport>=1 and dstport<=65535": 0,
                "policyid==42 and proto==6 and dstport==443": 6,
                "policyid==42 and proto==6 and dstport>=1 and dstport<=442": 0,
                "policyid==42 and proto==6 and dstport>=444 and dstport<=65535": 4,
                "policyid==42 and proto==1 and service==PING": 2,
                'policyid==42 and proto==1 and service=="icmp/3/3"': 1,
            }
            if filter_str not in mapping:
                raise AssertionError(f"Unexpected filter in test: {filter_str}")
            return mapping[filter_str]

        async def fake_discover_policy_candidates(**kwargs):
            policy_filter = kwargs["policy_filter"]
            if policy_filter == "policyid==42":
                return {"dstport": Counter({"443": 10})}, {"errors": []}
            if policy_filter == "policyid==42 and proto==1":
                return {"service": Counter({"PING": 2, "icmp/3/3": 1})}, {"errors": []}
            raise AssertionError(f"Unexpected policy_filter: {policy_filter}")

        async def fake_enumerate_exact_protocols(**kwargs):
            return [{"protocol": "6", "hits": 10}, {"protocol": "1", "hits": 3}]

        async def fake_enumerate_exact_ports(**kwargs):
            assert kwargs["base_filter"] == "policyid==42 and proto==6"
            assert kwargs["low"] == 444
            assert kwargs["high"] == 65535
            assert kwargs["known_hits"] == 4
            return [{"port": "8443", "hits": 4}]

        monkeypatch.setattr(traffic_tools, "_run_log_count_exact", fake_run_log_count_exact)
        monkeypatch.setattr(
            traffic_tools,
            "_discover_policy_candidates",
            fake_discover_policy_candidates,
        )
        monkeypatch.setattr(
            traffic_tools,
            "_enumerate_exact_protocols",
            fake_enumerate_exact_protocols,
        )
        monkeypatch.setattr(
            traffic_tools,
            "_enumerate_exact_ports",
            fake_enumerate_exact_ports,
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
    ) -> None:
        """`uncovered_port_hits` should only represent missing numeric port coverage."""

        async def fake_run_log_count_exact(**kwargs):
            filter_str = kwargs.get("filter_str") or ""
            mapping = {
                "policyid==42": 13,
                "policyid==42 and proto>=0 and proto<=255": 13,
                "policyid==42 and dstport>=1 and dstport<=65535": 12,
                "policyid==42 and proto==6 and dstport>=1 and dstport<=65535": 12,
                "policyid==42 and proto==1 and dstport>=1 and dstport<=65535": 0,
                "policyid==42 and proto==6 and dstport==443": 6,
                "policyid==42 and proto==6 and dstport>=1 and dstport<=442": 0,
                "policyid==42 and proto==6 and dstport>=444 and dstport<=65535": 6,
                "policyid==42 and proto==1 and service==PING": 1,
            }
            if filter_str not in mapping:
                raise AssertionError(f"Unexpected filter in test: {filter_str}")
            return mapping[filter_str]

        async def fake_discover_policy_candidates(**kwargs):
            policy_filter = kwargs["policy_filter"]
            if policy_filter == "policyid==42":
                return {"dstport": Counter({"443": 10})}, {"errors": []}
            if policy_filter == "policyid==42 and proto==1":
                return {"service": Counter({"PING": 1})}, {"errors": []}
            raise AssertionError(f"Unexpected policy_filter: {policy_filter}")

        async def fake_enumerate_exact_protocols(**kwargs):
            return [{"protocol": "6", "hits": 12}, {"protocol": "1", "hits": 1}]

        async def fake_enumerate_exact_ports(**kwargs):
            return [{"port": "8443", "hits": 4}]

        monkeypatch.setattr(traffic_tools, "_run_log_count_exact", fake_run_log_count_exact)
        monkeypatch.setattr(
            traffic_tools,
            "_discover_policy_candidates",
            fake_discover_policy_candidates,
        )
        monkeypatch.setattr(
            traffic_tools,
            "_enumerate_exact_protocols",
            fake_enumerate_exact_protocols,
        )
        monkeypatch.setattr(
            traffic_tools,
            "_enumerate_exact_ports",
            fake_enumerate_exact_ports,
        )

        result = await traffic_tools.get_policy_port_analysis(
            policy_ids=[42],
            adom="root",
            time_range="1-day",
        )

        policy = result["results"][0]
        assert policy["is_exact"] is False
        assert policy["uncovered_port_hits"] == 2
        assert policy["icmp"] == [{"type_code": "type=8/code=0", "hits": 1}]


class TestPolicyProtocolSummaryTool:
    """Tests for protocol summary behavior."""

    async def test_protocol_summary_uses_exact_protocol_counts(self, monkeypatch) -> None:
        """Protocol summaries should be built from exact protocol counts."""

        async def fake_run_log_count_exact(**kwargs):
            filter_str = kwargs.get("filter_str") or ""
            mapping = {
                "policyid==42": 4,
                "policyid==42 and proto>=0 and proto<=255": 4,
            }
            if filter_str not in mapping:
                raise AssertionError(f"Unexpected filter in test: {filter_str}")
            return mapping[filter_str]

        async def fake_enumerate_exact_protocols(**kwargs):
            return [
                {"protocol": "6", "hits": 2},
                {"protocol": "17", "hits": 1},
                {"protocol": "1", "hits": 1},
            ]

        monkeypatch.setattr(traffic_tools, "_run_log_count_exact", fake_run_log_count_exact)
        monkeypatch.setattr(
            traffic_tools,
            "_enumerate_exact_protocols",
            fake_enumerate_exact_protocols,
        )

        result = await traffic_tools.get_policy_protocol_summary(
            policy_ids=[42],
            adom="root",
            time_range="24-hour",
        )

        assert result["status"] == "success"
        assert result["results"][0] == {
            "policy_id": 42,
            "total_hits": 4,
            "protocols": [
                {"protocol": "TCP", "hits": 2},
                {"protocol": "ICMP", "hits": 1},
                {"protocol": "UDP", "hits": 1},
            ],
        }
