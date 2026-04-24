"""Policy traffic analysis tools for FortiAnalyzer.

Provides tools for analyzing observed traffic patterns per firewall policy:
- sampled traffic profiling (top ports, services, applications)
- exact port and protocol analysis with truthful exactness semantics
- lightweight protocol distribution summaries

These tools support policy-review and policy-tightening preparation workflows.
"""

import asyncio
import hashlib
import json
import logging
import math
import os
import time
import uuid
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, TypedDict, cast

from fortianalyzer_mcp.server import get_faz_client, mcp
from fortianalyzer_mcp.utils.errors import (
    APIError,
)
from fortianalyzer_mcp.utils.errors import (
    ConnectionError as FazConnectionError,
)
from fortianalyzer_mcp.utils.errors import (
    TimeoutError as FazTimeoutError,
)
from fortianalyzer_mcp.utils.validation import (
    VALID_TRAFFIC_ACTIONS,
    ValidationError,
    get_default_adom,
    sanitize_filter_value,
    validate_adom,
    validate_positive_int,
    validate_traffic_action,
)

logger = logging.getLogger(__name__)

_SLICE_ALIGNMENT_EPOCH = datetime(1970, 1, 1)

# Concurrency limit for per-policy work.
_POLICY_QUERY_SEMAPHORE = asyncio.Semaphore(5)

# Default and max search parameters.
DEFAULT_SEARCH_TIMEOUT = 120
POLL_INTERVAL = 0.25
MAX_POLICY_IDS = 25
DEFAULT_TOP_N = 10
DEFAULT_POLICY_PROFILE_TIMEOUT = 20
DEFAULT_PORT_ANALYSIS_FETCH_TIMEOUT = 30
DEFAULT_PORT_ANALYSIS_BACKGROUND_FETCH_TIMEOUT = 120
DEFAULT_PORT_ANALYSIS_BACKGROUND_MIN_SPLIT_MINUTES = 1
DEFAULT_PORT_ANALYSIS_SYNC_BUDGET_SECONDS = 90
DEFAULT_PORT_ANALYSIS_TARGET_HITS_PER_SLICE = 1000
DEFAULT_PORT_ANALYSIS_MIN_SLICE_MINUTES = 60
DEFAULT_PORT_ANALYSIS_MIN_RETRY_SPLIT_MINUTES = 5
DEFAULT_PORT_ANALYSIS_MAX_FORTIVIEW_ROWS = 1000
DEFAULT_PORT_ANALYSIS_MAX_PLAN_SLICES = 48
DEFAULT_PORT_ANALYSIS_MAX_PLAN_TOTAL_PAGES = 150
DEFAULT_PORT_ANALYSIS_MAX_PAGES_PER_SLICE = 10
DEFAULT_PORT_ANALYSIS_SLICE_CONCURRENCY = 3
DEFAULT_PORT_ANALYSIS_BACKGROUND_JOB_CONCURRENCY = 1
DEFAULT_PORT_ANALYSIS_ESTIMATED_SECONDS_PER_SLICE = 1.0
DEFAULT_PORT_ANALYSIS_ESTIMATED_SECONDS_PER_PAGE = 0.5
DEFAULT_EXACT_FETCH_PAGE_SIZE = 500
PORT_ANALYSIS_CACHE_VERSION = 1
PORT_ANALYSIS_JOB_SCHEMA_VERSION = 1
DEFAULT_POLICY_SAMPLE_LIMIT = 25
DEFAULT_POLICY_CANDIDATE_LIMIT = 12
DEFAULT_PORT_ANALYSIS_CANDIDATE_LIMIT = 4
DEFAULT_POLICY_MAX_DISCOVERY_SLICES = 4
DEFAULT_BATCH_DISCOVERY_QUERY_BUDGET = 24
DEFAULT_EXACT_MIN_SPLIT_HOURS = 6
DEFAULT_EXACT_SLICE_DAYS = 15
DEFAULT_PROTOCOL_COUNT_CONCURRENCY = 4
DEFAULT_VALUE_RECOUNT_CONCURRENCY = 3
DEFAULT_PORT_ANALYSIS_RECOUNT_CONCURRENCY = 4
DEFAULT_PORT_ANALYSIS_COUNT_TIMEOUT = 8
DEFAULT_DISCOVERED_PROTOCOL_LIMIT = 4

PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    33: "DCCP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

PORT_BEARING_PROTOCOLS = {6, 17, 33, 132}
SUMMARY_BASE_PROTOCOLS = (6, 17, 1)
PORT_ANALYSIS_BASE_PROTOCOLS = (6, 17, 33, 132, 1, 47, 50)
VALID_ACTIONS = frozenset(VALID_TRAFFIC_ACTIONS)

RETRYABLE_QUERY_EXCEPTIONS = (
    RuntimeError,
    OSError,
    TimeoutError,
    FazConnectionError,
    FazTimeoutError,
    APIError,
)

_PORT_ANALYSIS_JOB_TASKS: dict[str, asyncio.Task[None]] = {}
_PORT_ANALYSIS_JOB_SEMAPHORE = asyncio.Semaphore(
    DEFAULT_PORT_ANALYSIS_BACKGROUND_JOB_CONCURRENCY
)
PortAnalysisProgressCallback = Callable[[str, dict[str, Any]], Awaitable[None] | None]


def _get_repo_root() -> Path:
    """Return the repository root for local cache storage."""
    return Path(__file__).resolve().parents[3]


def _get_port_analysis_cache_root() -> Path:
    """Return the root directory for cached exact-analysis state."""
    override = os.getenv("FAZ_TRAFFIC_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    return _get_repo_root() / ".cache" / "traffic_tools"


def _get_port_analysis_slice_cache_dir() -> Path:
    """Return the directory for persisted exact slice accumulators."""
    return _get_port_analysis_cache_root() / "slices"


def _get_port_analysis_jobs_dir() -> Path:
    """Return the directory for persisted background-job state."""
    return _get_port_analysis_cache_root() / "jobs"


def _utc_timestamp() -> str:
    """Render a stable local timestamp for cache/job metadata."""
    return datetime.now().isoformat(timespec="seconds")


def _ensure_parent_dir(path: Path) -> None:
    """Create parent directories for a cache/job file."""
    path.parent.mkdir(parents=True, exist_ok=True)


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    """Write JSON atomically so cache/job files are never partially replaced."""
    _ensure_parent_dir(path)
    temp_path = path.with_suffix(f"{path.suffix}.tmp-{uuid.uuid4().hex}")
    temp_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    temp_path.replace(path)


def _read_json_file(path: Path) -> dict[str, Any] | None:
    """Read one JSON cache/job file if it exists and parses cleanly."""
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to read cached traffic-analysis file %s: %s", path, exc)
        return None
    return payload if isinstance(payload, dict) else None


def _normalize_device_filter_for_cache(
    device_filter: list[dict[str, str]],
) -> list[dict[str, str]]:
    """Normalize device filters into a stable cache-key representation."""
    normalized = [dict(sorted(item.items())) for item in device_filter]
    normalized.sort(key=lambda item: json.dumps(item, sort_keys=True))
    return normalized


def _build_port_analysis_cache_key_payload(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    policy_id: int,
    action: str | None,
    time_range: dict[str, str],
) -> dict[str, Any]:
    """Build the canonical cache-key payload for one exact policy/time slice."""
    return {
        "version": PORT_ANALYSIS_CACHE_VERSION,
        "adom": adom,
        "device_filter": _normalize_device_filter_for_cache(device_filter),
        "policy_id": policy_id,
        "action": action,
        "time_range": time_range,
    }


def _build_port_analysis_cache_path(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    policy_id: int,
    action: str | None,
    time_range: dict[str, str],
) -> Path:
    """Return the on-disk cache path for one exact policy/time slice."""
    payload = _build_port_analysis_cache_key_payload(
        adom=adom,
        device_filter=device_filter,
        policy_id=policy_id,
        action=action,
        time_range=time_range,
    )
    cache_key = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return _get_port_analysis_slice_cache_dir() / f"{cache_key}.json"


def _build_port_analysis_job_path(job_id: str) -> Path:
    """Return the on-disk path for one background job state file."""
    return _get_port_analysis_jobs_dir() / f"{job_id}.json"


async def _emit_port_analysis_progress(
    callback: PortAnalysisProgressCallback | None,
    event: str,
    payload: dict[str, Any],
) -> None:
    """Deliver one optional progress event to a caller."""
    if callback is None:
        return
    maybe_result = callback(event, payload)
    if asyncio.iscoroutine(maybe_result):
        await maybe_result


class DiscoveryQueryShape(TypedDict):
    """Configuration for one discovery-sampling query shape."""

    name: str
    extra_filter: str | None
    offsets: list[int]


class CountError(TypedDict):
    """A structured recount error for one discovered value."""

    field: str
    value: str
    message: str


class PortHit(TypedDict):
    """A destination port hit count."""

    port: str
    hits: int


class ProtocolHit(TypedDict):
    """A protocol hit count."""

    protocol: str
    hits: int


class ICMPTypeHit(TypedDict):
    """An ICMP type/code hit count."""

    type_code: str
    hits: int


@dataclass(slots=True)
class PortAnalysisEstimate:
    """Cost estimate metadata for one exact port-analysis request."""

    hits_by_policy: dict[int, int] = field(default_factory=dict)
    complete: bool = False

    @property
    def total_hits(self) -> int:
        """Total estimated hits across all discovered policies."""
        return sum(self.hits_by_policy.values())


@dataclass(slots=True)
class PortAnalysisRunPlan:
    """Execution plan for one synchronous exact port-analysis request."""

    estimate: PortAnalysisEstimate
    policy_slice_minutes: dict[int, int] = field(default_factory=dict)
    policy_estimated_slices: dict[int, int] = field(default_factory=dict)
    policy_estimated_pages: dict[int, int] = field(default_factory=dict)
    max_pages_per_slice: int = 0
    estimated_total_slices: int = 0
    estimated_total_pages: int = 0
    estimated_wall_seconds: float = 0.0
    should_execute: bool = True
    reason: str | None = None


@dataclass(slots=True)
class PortAnalysisAccumulator:
    """Incrementally aggregate exact port-analysis results."""

    total_hits: int = 0
    port_counter: Counter[str] = field(default_factory=Counter)
    protocol_counter: Counter[str] = field(default_factory=Counter)
    portless_protocols: set[str] = field(default_factory=set)
    icmp_types: Counter[str] = field(default_factory=Counter)

    def consume_rows(self, rows: list[dict[str, Any]]) -> None:
        """Consume one fetched log page."""
        for log in rows:
            proto_str = str(log.get("proto", "unknown")).strip() or "unknown"
            self.protocol_counter[proto_str] += 1
            self.total_hits += 1

            dstport = log.get("dstport")
            if dstport is not None and str(dstport).isdigit() and str(dstport) != "0":
                self.port_counter[f"{proto_str}/{dstport}"] += 1
            else:
                self.portless_protocols.add(proto_str)

            if proto_str == "1":
                service = str(log.get("service", ""))
                if service:
                    self.icmp_types[_format_icmp_type_code(service)] += 1

    def merge(self, other: "PortAnalysisAccumulator") -> None:
        """Merge another exact-analysis accumulator into this one."""
        self.total_hits += other.total_hits
        self.port_counter.update(other.port_counter)
        self.protocol_counter.update(other.protocol_counter)
        self.portless_protocols.update(other.portless_protocols)
        self.icmp_types.update(other.icmp_types)

    def to_cache_dict(self) -> dict[str, Any]:
        """Serialize this accumulator to a cache-friendly JSON structure."""
        return {
            "total_hits": self.total_hits,
            "port_counter": dict(self.port_counter),
            "protocol_counter": dict(self.protocol_counter),
            "portless_protocols": sorted(self.portless_protocols, key=_protocol_sort_key),
            "icmp_types": dict(self.icmp_types),
        }

    @classmethod
    def from_cache_dict(cls, payload: dict[str, Any]) -> "PortAnalysisAccumulator":
        """Rebuild an accumulator from cached JSON data."""
        accumulator = cls()
        accumulator.total_hits = int(payload.get("total_hits", 0) or 0)
        accumulator.port_counter = Counter(
            {
                str(port): int(hits)
                for port, hits in dict(payload.get("port_counter", {})).items()
            }
        )
        accumulator.protocol_counter = Counter(
            {
                str(protocol): int(hits)
                for protocol, hits in dict(payload.get("protocol_counter", {})).items()
            }
        )
        accumulator.portless_protocols = {
            str(protocol)
            for protocol in list(payload.get("portless_protocols", []))
            if str(protocol)
        }
        accumulator.icmp_types = Counter(
            {
                str(type_code): int(hits)
                for type_code, hits in dict(payload.get("icmp_types", {})).items()
            }
        )
        return accumulator

    def build_result(self, *, is_exact: bool = True) -> dict[str, Any]:
        """Render the final exact-analysis structure."""
        return {
            "total_hits": self.total_hits,
            "is_exact": is_exact,
            "ports": sorted(
                [{"port": port, "hits": hits} for port, hits in self.port_counter.items()],
                key=lambda item: (
                    -int(item["hits"]),
                    _port_pair_sort_key(str(item["port"])),
                ),
            ),
            "protocols": sorted(
                [
                    {"protocol": protocol, "hits": hits}
                    for protocol, hits in self.protocol_counter.items()
                ],
                key=lambda item: (
                    -int(item["hits"]),
                    _protocol_sort_key(str(item["protocol"])),
                ),
            ),
            "portless_protocols": sorted(self.portless_protocols, key=_protocol_sort_key),
            "uncovered_port_hits": 0 if is_exact else self.total_hits,
            "icmp": sorted(
                [
                    {"type_code": type_code, "hits": hits}
                    for type_code, hits in self.icmp_types.items()
                ],
                key=lambda item: (-int(item["hits"]), str(item["type_code"])),
            ),
        }


def _load_cached_port_analysis_accumulator(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    policy_id: int,
    action: str | None,
    time_range: dict[str, str],
) -> PortAnalysisAccumulator | None:
    """Load a cached exact-analysis accumulator for one policy/time slice."""
    cache_path = _build_port_analysis_cache_path(
        adom=adom,
        device_filter=device_filter,
        policy_id=policy_id,
        action=action,
        time_range=time_range,
    )
    payload = _read_json_file(cache_path)
    if not payload or payload.get("version") != PORT_ANALYSIS_CACHE_VERSION:
        return None
    accumulator_payload = payload.get("accumulator")
    if not isinstance(accumulator_payload, dict):
        return None
    return PortAnalysisAccumulator.from_cache_dict(accumulator_payload)


def _store_cached_port_analysis_accumulator(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    policy_id: int,
    action: str | None,
    time_range: dict[str, str],
    accumulator: PortAnalysisAccumulator,
) -> None:
    """Persist an exact-analysis accumulator for one policy/time slice."""
    cache_path = _build_port_analysis_cache_path(
        adom=adom,
        device_filter=device_filter,
        policy_id=policy_id,
        action=action,
        time_range=time_range,
    )
    payload = {
        "version": PORT_ANALYSIS_CACHE_VERSION,
        "cached_at": _utc_timestamp(),
        "request": _build_port_analysis_cache_key_payload(
            adom=adom,
            device_filter=device_filter,
            policy_id=policy_id,
            action=action,
            time_range=time_range,
        ),
        "accumulator": accumulator.to_cache_dict(),
    }
    _write_json_atomic(cache_path, payload)


def _has_cached_port_analysis_accumulator(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    policy_id: int,
    action: str | None,
    time_range: dict[str, str],
) -> bool:
    """Return True when a full exact accumulator is already cached."""
    return (
        _load_cached_port_analysis_accumulator(
            adom=adom,
            device_filter=device_filter,
            policy_id=policy_id,
            action=action,
            time_range=time_range,
        )
        is not None
    )


def _load_cached_port_analysis_accumulator_recursive(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    policy_id: int,
    action: str | None,
    time_range: dict[str, str],
    min_split_minutes: int,
) -> PortAnalysisAccumulator | None:
    """Load one cached slice or reconstruct it from cached descendants."""
    cached = _load_cached_port_analysis_accumulator(
        adom=adom,
        device_filter=device_filter,
        policy_id=policy_id,
        action=action,
        time_range=time_range,
    )
    if cached is not None:
        return cached

    start, end = _parse_time_range_dict(time_range)
    if end - start <= timedelta(minutes=max(min_split_minutes, 1)):
        return None

    split_ranges = _split_time_range_non_overlapping(time_range)
    if not split_ranges:
        return None

    left_range, right_range = split_ranges
    left_cached = _load_cached_port_analysis_accumulator_recursive(
        adom=adom,
        device_filter=device_filter,
        policy_id=policy_id,
        action=action,
        time_range=left_range,
        min_split_minutes=min_split_minutes,
    )
    if left_cached is None:
        return None

    right_cached = _load_cached_port_analysis_accumulator_recursive(
        adom=adom,
        device_filter=device_filter,
        policy_id=policy_id,
        action=action,
        time_range=right_range,
        min_split_minutes=min_split_minutes,
    )
    if right_cached is None:
        return None

    merged = PortAnalysisAccumulator()
    merged.merge(left_cached)
    merged.merge(right_cached)
    _store_cached_port_analysis_accumulator(
        adom=adom,
        device_filter=device_filter,
        policy_id=policy_id,
        action=action,
        time_range=time_range,
        accumulator=merged,
    )
    return merged


def _load_port_analysis_job_state(job_id: str) -> dict[str, Any] | None:
    """Load one persisted background exact-analysis job state."""
    job_path = _build_port_analysis_job_path(job_id)
    payload = _read_json_file(job_path)
    if not payload or payload.get("version") != PORT_ANALYSIS_JOB_SCHEMA_VERSION:
        return None
    return payload


def _store_port_analysis_job_state(job_state: dict[str, Any]) -> None:
    """Persist one background exact-analysis job state."""
    job_path = _build_port_analysis_job_path(str(job_state["job_id"]))
    _write_json_atomic(job_path, job_state)


def _serialize_port_analysis_estimate(estimate: "PortAnalysisEstimate") -> dict[str, Any]:
    """Serialize one policy-hit estimate into persisted job state."""
    return {
        "hits_by_policy": estimate.hits_by_policy,
        "complete": estimate.complete,
    }


def _deserialize_port_analysis_estimate(payload: dict[str, Any] | None) -> "PortAnalysisEstimate":
    """Rebuild one policy-hit estimate from persisted job state."""
    if not isinstance(payload, dict):
        return PortAnalysisEstimate()
    raw_hits = payload.get("hits_by_policy", {})
    hits_by_policy = {
        int(policy_id): int(hits)
        for policy_id, hits in dict(raw_hits).items()
    }
    return PortAnalysisEstimate(
        hits_by_policy=hits_by_policy,
        complete=bool(payload.get("complete", False)),
    )


def validate_action(action: str | None) -> str | None:
    """Validate an optional traffic log action."""
    if action is None:
        return None
    return validate_traffic_action(action)


def validate_policy_ids(policy_ids: list[int]) -> list[int]:
    """Validate, normalize, and de-duplicate policy IDs."""
    if not policy_ids:
        raise ValidationError("policy_ids must not be empty")

    normalized: list[int] = []
    seen: set[int] = set()
    for policy_id in policy_ids:
        value = validate_positive_int(policy_id, "policy_id")
        if value not in seen:
            seen.add(value)
            normalized.append(value)

    if len(normalized) > MAX_POLICY_IDS:
        raise ValidationError(
            f"Too many policy IDs ({len(normalized)}). Maximum is {MAX_POLICY_IDS}."
        )

    return normalized


def _get_client() -> Any:
    """Get the FortiAnalyzer client instance."""
    client = get_faz_client()
    if not client:
        raise RuntimeError("FortiAnalyzer client not initialized")
    return client


async def _get_connected_client() -> Any:
    """Get a connected FortiAnalyzer client."""
    client = _get_client()
    if not client.is_connected:
        await client.connect()
    return client


def _parse_time_range(time_range: str) -> dict[str, str]:
    """Parse time range string to API format."""
    now = datetime.now()
    fmt = "%Y-%m-%d %H:%M:%S"

    if "|" in time_range:
        parts = time_range.split("|", maxsplit=1)
        return {"start": parts[0].strip(), "end": parts[1].strip()}

    range_map = {
        "1-hour": timedelta(hours=1),
        "6-hour": timedelta(hours=6),
        "12-hour": timedelta(hours=12),
        "24-hour": timedelta(hours=24),
        "1-day": timedelta(days=1),
        "7-day": timedelta(days=7),
        "30-day": timedelta(days=30),
    }

    delta = range_map.get(time_range, timedelta(hours=1))
    start = now - delta
    return {"start": start.strftime(fmt), "end": now.strftime(fmt)}


def _build_device_filter(device: str | None) -> list[dict[str, str]]:
    """Build device filter for the FAZ API."""
    if not device:
        return [{"devid": "All_FortiGate"}]
    if device.startswith(("FG", "FM", "FW", "FA", "FS", "FD", "FP", "FC")):
        return [{"devid": device}]
    if device.startswith("All_"):
        return [{"devid": device}]
    return [{"devname": device}]


def _combine_filters(*filters: str | None) -> str | None:
    """Combine filter fragments using FortiAnalyzer syntax."""
    parts = [item.strip() for item in filters if item and item.strip()]
    return " and ".join(parts) if parts else None


def _parse_time_range_bounds(time_range: str) -> tuple[datetime, datetime]:
    """Parse a time range string into datetime bounds."""
    parsed = _parse_time_range(time_range)
    fmt = "%Y-%m-%d %H:%M:%S"
    return datetime.strptime(parsed["start"], fmt), datetime.strptime(parsed["end"], fmt)


def _format_time_range(start: datetime, end: datetime) -> dict[str, str]:
    """Format datetime bounds for FortiAnalyzer APIs."""
    fmt = "%Y-%m-%d %H:%M:%S"
    return {"start": start.strftime(fmt), "end": end.strftime(fmt)}


def _parse_time_range_dict(time_range: dict[str, str]) -> tuple[datetime, datetime]:
    """Parse a FortiAnalyzer time-range dict into datetime bounds."""
    fmt = "%Y-%m-%d %H:%M:%S"
    return datetime.strptime(time_range["start"], fmt), datetime.strptime(time_range["end"], fmt)


def _split_time_range_non_overlapping(
    time_range: dict[str, str],
) -> tuple[dict[str, str], dict[str, str]] | None:
    """Split a time range into two non-overlapping second-aligned ranges."""
    start, end = _parse_time_range_dict(time_range)
    span_seconds = int((end - start).total_seconds())
    if span_seconds <= 0:
        return None

    left_end = start + timedelta(seconds=span_seconds // 2)
    right_start = left_end + timedelta(seconds=1)
    if right_start > end:
        return None

    return _format_time_range(start, left_end), _format_time_range(right_start, end)


def _build_exact_time_slices(
    time_range: dict[str, str],
    slice_days: int,
) -> list[dict[str, str]]:
    """Build non-overlapping exact-count slices with second-level boundaries."""
    if slice_days <= 0:
        return [time_range]

    start, end = _parse_time_range_dict(time_range)
    if end <= start:
        return [time_range]

    step_seconds = max(int(timedelta(days=slice_days).total_seconds()), 1)
    cursor = start
    slices = []
    while cursor <= end:
        slice_end = min(cursor + timedelta(seconds=step_seconds - 1), end)
        slices.append(_format_time_range(cursor, slice_end))
        cursor = slice_end + timedelta(seconds=1)
    return slices


def _build_exact_slice_day_candidates(preferred_slice_days: int) -> list[int]:
    """Build descending exact slice-day candidates ending at 1 day."""
    days = max(preferred_slice_days, 1)
    candidates = []
    while days > 1:
        candidates.append(days)
        next_days = max(days // 2, 1)
        if next_days == days:
            break
        days = next_days
    candidates.append(1)
    return list(dict.fromkeys(candidates))


def _build_exact_time_slices_minutes(
    time_range: dict[str, str],
    slice_minutes: int,
) -> list[dict[str, str]]:
    """Build non-overlapping exact slices using stable minute-level boundaries.

    The first and last slices may be partial, but interior slices align to a
    deterministic wall-clock grid so overlapping reruns can reuse cached exact
    slice results instead of starting from a shifted relative-window origin.
    """
    step_minutes = max(slice_minutes, DEFAULT_PORT_ANALYSIS_MIN_SLICE_MINUTES)
    start, end = _parse_time_range_dict(time_range)
    if end <= start:
        return [time_range]

    step_seconds = max(int(timedelta(minutes=step_minutes).total_seconds()), 1)
    slices = []
    cursor = start
    start_offset = int((start - _SLICE_ALIGNMENT_EPOCH).total_seconds()) % step_seconds

    if start_offset:
        first_end = min(end, start + timedelta(seconds=step_seconds - start_offset - 1))
        slices.append(_format_time_range(start, first_end))
        cursor = first_end + timedelta(seconds=1)

    while cursor <= end:
        slice_end = min(cursor + timedelta(seconds=step_seconds - 1), end)
        slices.append(_format_time_range(cursor, slice_end))
        cursor = slice_end + timedelta(seconds=1)
    return slices


def _estimate_slice_count(start: datetime, end: datetime, slice_days: int) -> int:
    """Estimate how many slices a time range would produce."""
    if end <= start:
        return 1

    step_seconds = max(int(timedelta(days=max(slice_days, 1)).total_seconds()), 1)
    span_seconds = max(int((end - start).total_seconds()), 0)
    return max(1, math.ceil(span_seconds / step_seconds))


def _build_time_slices(
    time_range: str,
    slice_days: int,
    max_slices: int = DEFAULT_POLICY_MAX_DISCOVERY_SLICES,
) -> list[dict[str, str]]:
    """Split a time range into smaller slices for discovery sampling."""
    start, end = _parse_time_range_bounds(time_range)
    if end <= start:
        return [_format_time_range(start, end)]

    requested_slice_days = max(slice_days, 1)
    requested_slices = _estimate_slice_count(start, end, requested_slice_days)

    effective_slice_days = requested_slice_days
    if max_slices > 0 and requested_slices > max_slices:
        span_days = max((end - start).total_seconds() / 86400, 0)
        effective_slice_days = max(1, math.ceil(span_days / max_slices))

    step = timedelta(days=effective_slice_days)
    cursor = start
    slices = []
    while cursor < end:
        next_cursor = min(cursor + step, end)
        slices.append(_format_time_range(cursor, next_cursor))
        cursor = next_cursor
    return slices


def _estimate_discovery_queries_per_slice(fields: tuple[str, ...]) -> int:
    """Estimate discovery query fan-out for one time slice."""
    return 3 if "port_pair" in fields or "dstport" in fields else 1


def _plan_batch_slice_days(
    *,
    time_range: str,
    slice_days: int,
    policy_count: int,
    fields: tuple[str, ...],
) -> int:
    """Increase slice size for large batch requests to keep discovery bounded."""
    if policy_count <= 1:
        return max(slice_days, 1)

    start, end = _parse_time_range_bounds(time_range)
    requested_slice_days = max(slice_days, 1)
    requested_slices = _estimate_slice_count(start, end, requested_slice_days)
    per_slice_queries = _estimate_discovery_queries_per_slice(fields)
    max_slices_per_policy = max(
        1,
        DEFAULT_BATCH_DISCOVERY_QUERY_BUDGET // max(policy_count * per_slice_queries, 1),
    )

    if requested_slices <= max_slices_per_policy:
        return requested_slice_days

    span_days = max((end - start).total_seconds() / 86400, 0)
    return max(requested_slice_days, math.ceil(span_days / max_slices_per_policy))


def _format_span_label(span: timedelta) -> str:
    """Render a compact span label for error messages."""
    total_seconds = max(int(span.total_seconds()), 0)
    if total_seconds % 86400 == 0 and total_seconds >= 86400:
        return f"{total_seconds // 86400}-day"
    if total_seconds % 3600 == 0 and total_seconds >= 3600:
        return f"{total_seconds // 3600}-hour"
    return f"{total_seconds}s"


def _normalize_fortiview_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize one FortiView fetch payload into a list of row dicts."""
    rows = result.get("data", [])
    if not isinstance(rows, list):
        rows = [rows] if rows else []
    return [row for row in rows if isinstance(row, dict)]


def _parse_fortiview_hit_count(row: dict[str, Any], action: str | None) -> int | None:
    """Extract a conservative per-policy hit estimate from one FortiView row."""
    key = "counts"
    if action == "accept":
        key = "count_pass"
    elif action == "deny":
        key = "count_block"

    raw = row.get(key)
    if raw is None and key != "counts":
        raw = row.get("counts")
    if raw is None:
        return None

    try:
        return max(int(raw), 0)
    except (TypeError, ValueError):
        return None


async def _run_fortiview_page(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    offset: int,
    limit: int,
    timeout: int,
) -> list[dict[str, Any]]:
    """Fetch one page of FortiView policy-hit rows."""
    client = await _get_connected_client()
    run_result = await client.fortiview_run(
        adom=adom,
        view_name="policy-hits",
        device=device_filter,
        time_range=time_range,
        limit=limit,
        offset=offset,
        sort_by=[{"field": "counts", "order": "desc"}],
    )
    tid = run_result.get("tid")
    if not tid:
        raise RuntimeError(f"No TID returned for FortiView policy-hits query: {run_result}")

    started = time.monotonic()
    while True:
        if time.monotonic() - started > timeout:
            raise TimeoutError(
                f"FortiView policy-hits query timed out after {timeout}s at offset {offset}"
            )

        result = await client.fortiview_fetch(
            adom=adom,
            view_name="policy-hits",
            tid=tid,
        )
        if result.get("percentage", 100) >= 100:
            return _normalize_fortiview_rows(result)

        await asyncio.sleep(POLL_INTERVAL)


async def _estimate_port_analysis_hits(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    full_time_range: dict[str, str],
    policy_ids: list[int],
    action: str | None,
) -> PortAnalysisEstimate:
    """Estimate exact port-analysis cost from FortiView policy hits."""
    page_size = min(100, DEFAULT_PORT_ANALYSIS_MAX_FORTIVIEW_ROWS)
    max_rows = max(page_size, DEFAULT_PORT_ANALYSIS_MAX_FORTIVIEW_ROWS)
    remaining = set(policy_ids)
    hits_by_policy: dict[int, int] = {}

    try:
        for offset in range(0, max_rows, page_size):
            rows = await _run_fortiview_page(
                adom=adom,
                device_filter=device_filter,
                time_range=full_time_range,
                offset=offset,
                limit=min(page_size, max_rows - offset),
                timeout=DEFAULT_PORT_ANALYSIS_SYNC_BUDGET_SECONDS,
            )

            for row in rows:
                if row.get("policytype") != "policy":
                    continue

                policy_id_raw = row.get("agg_policyid")
                if policy_id_raw is None or not str(policy_id_raw).isdigit():
                    continue

                policy_id = int(policy_id_raw)
                if policy_id not in remaining:
                    continue

                hits = _parse_fortiview_hit_count(row, action)
                if hits is None:
                    continue

                hits_by_policy[policy_id] = hits
                remaining.discard(policy_id)

            if not rows or len(rows) < page_size or not remaining:
                break
    except RETRYABLE_QUERY_EXCEPTIONS as exc:
        logger.warning(f"Policy-hits estimate failed, falling back to heuristics: {exc}")
        return PortAnalysisEstimate(hits_by_policy=hits_by_policy, complete=False)

    return PortAnalysisEstimate(
        hits_by_policy=hits_by_policy,
        complete=not remaining and len(hits_by_policy) == len(policy_ids),
    )


def _plan_port_analysis_slice_minutes(
    *,
    full_time_range: dict[str, str],
    estimated_hits: int | None,
) -> int:
    """Plan initial exact-fetch slice size for one policy."""
    start, end = _parse_time_range_dict(full_time_range)
    span = max(end - start, timedelta(seconds=1))

    if estimated_hits is not None and estimated_hits > 0:
        slice_count = max(
            1,
            math.ceil(estimated_hits / DEFAULT_PORT_ANALYSIS_TARGET_HITS_PER_SLICE),
        )
        raw_minutes = math.ceil(span.total_seconds() / 60 / slice_count)
        return max(DEFAULT_PORT_ANALYSIS_MIN_SLICE_MINUTES, min(raw_minutes, 24 * 60))

    if span <= timedelta(days=1):
        return 60
    if span <= timedelta(days=7):
        return 6 * 60
    if span <= timedelta(days=30):
        return 12 * 60
    return 24 * 60


def _estimate_port_analysis_pages(
    *,
    estimated_hits: int | None,
    estimated_slices: int,
) -> tuple[int, int]:
    """Estimate per-slice and total page fan-out for exact fetch planning."""
    if estimated_hits is None or estimated_hits <= 0:
        return 1, max(estimated_slices, 1)

    slices = max(estimated_slices, 1)
    hits_per_slice = max(1, math.ceil(estimated_hits / slices))
    pages_per_slice = max(1, math.ceil(hits_per_slice / DEFAULT_EXACT_FETCH_PAGE_SIZE))
    return pages_per_slice, slices * pages_per_slice


def _plan_port_analysis_run(
    *,
    policy_ids: list[int],
    full_time_range: dict[str, str],
    estimate: PortAnalysisEstimate,
) -> PortAnalysisRunPlan:
    """Plan whether a synchronous exact port-analysis request is feasible."""
    start, end = _parse_time_range_dict(full_time_range)
    span = max(end - start, timedelta(seconds=1))
    plan = PortAnalysisRunPlan(estimate=estimate)

    for policy_id in policy_ids:
        estimated_hits = estimate.hits_by_policy.get(policy_id)
        slice_minutes = _plan_port_analysis_slice_minutes(
            full_time_range=full_time_range,
            estimated_hits=estimated_hits,
        )
        estimated_slices = max(
            1,
            len(_build_exact_time_slices_minutes(full_time_range, slice_minutes)),
        )
        pages_per_slice, estimated_pages = _estimate_port_analysis_pages(
            estimated_hits=estimated_hits,
            estimated_slices=estimated_slices,
        )

        plan.policy_slice_minutes[policy_id] = slice_minutes
        plan.policy_estimated_slices[policy_id] = estimated_slices
        plan.policy_estimated_pages[policy_id] = estimated_pages
        plan.max_pages_per_slice = max(plan.max_pages_per_slice, pages_per_slice)
        plan.estimated_total_slices += estimated_slices
        plan.estimated_total_pages += estimated_pages

    plan.estimated_wall_seconds = round(
        plan.estimated_total_slices * DEFAULT_PORT_ANALYSIS_ESTIMATED_SECONDS_PER_SLICE
        + plan.estimated_total_pages * DEFAULT_PORT_ANALYSIS_ESTIMATED_SECONDS_PER_PAGE,
        2,
    )

    if span > timedelta(days=30):
        plan.should_execute = False
        plan.reason = "requested window exceeds 30 days"
        return plan

    if not estimate.complete and len(policy_ids) > 2 and span > timedelta(days=7):
        plan.should_execute = False
        plan.reason = "estimate unavailable for a high-fanout multi-policy window"
        return plan

    if plan.estimated_total_slices > DEFAULT_PORT_ANALYSIS_MAX_PLAN_SLICES:
        plan.should_execute = False
        plan.reason = "planned slice count exceeds synchronous budget"
        return plan

    if plan.estimated_total_pages > DEFAULT_PORT_ANALYSIS_MAX_PLAN_TOTAL_PAGES:
        plan.should_execute = False
        plan.reason = "planned page count exceeds synchronous budget"
        return plan

    if plan.max_pages_per_slice > DEFAULT_PORT_ANALYSIS_MAX_PAGES_PER_SLICE:
        plan.should_execute = False
        plan.reason = "one or more planned slices are too dense for synchronous execution"
        return plan

    if plan.estimated_wall_seconds > DEFAULT_PORT_ANALYSIS_SYNC_BUDGET_SECONDS:
        plan.should_execute = False
        plan.reason = "planned exact run exceeds the synchronous runtime budget"
        return plan

    return plan


def _build_port_analysis_guard_message(
    *,
    policy_ids: list[int],
    full_time_range: dict[str, str],
    plan: PortAnalysisRunPlan,
) -> str:
    """Build a fail-closed message for oversized exact port-analysis requests."""
    start, end = _parse_time_range_dict(full_time_range)
    span = end - start
    span_label = _format_span_label(span)
    missing = [
        str(policy_id)
        for policy_id in policy_ids
        if policy_id not in plan.estimate.hits_by_policy
    ]
    estimate_text = (
        f"estimated {plan.estimate.total_hits} hits"
        if plan.estimate.hits_by_policy
        else "FortiView estimate unavailable"
    )
    missing_text = (
        f"; missing estimate for policies {', '.join(missing)}"
        if missing
        else ""
    )
    return (
        "Exact policy port analysis plan exceeds the synchronous execution budget "
        f"({estimate_text} over {span_label}/{len(policy_ids)} policy request{missing_text}; "
        f"planned {plan.estimated_total_slices} slices / {plan.estimated_total_pages} pages; "
        f"estimated ~{plan.estimated_wall_seconds}s vs budget ~{DEFAULT_PORT_ANALYSIS_SYNC_BUDGET_SECONDS}s; "
        f"reason: {plan.reason or 'planned work too large'}). "
        "Split policies into separate calls, narrow the time_range, or add "
        "action='accept' or action='deny'."
    )


def _should_skip_port_analysis_estimate(
    *,
    policy_ids: list[int],
    full_time_range: dict[str, str],
) -> bool:
    """Skip FortiView estimation for request shapes already known to exceed budget."""
    start, end = _parse_time_range_dict(full_time_range)
    span = end - start
    if span > timedelta(days=30):
        return True
    return len(policy_ids) > 2 and span > timedelta(days=7)


def _port_analysis_guard_error(
    *,
    policy_ids: list[int],
    full_time_range: dict[str, str],
    plan: PortAnalysisRunPlan,
) -> str | None:
    """Return a fail-closed message when an exact request exceeds the sync budget."""
    if plan.should_execute:
        return None
    return _build_port_analysis_guard_message(
        policy_ids=policy_ids,
        full_time_range=full_time_range,
        plan=plan,
    )


def _normalize_sample_value(field: str, value: Any, row: dict[str, Any] | None = None) -> str | None:
    """Normalize a sampled log value for counting/filtering."""
    if field == "port_pair":
        if row is None:
            return None
        proto = str(row.get("proto", "")).strip()
        port = str(row.get("dstport", "")).strip()
        if not proto or not proto.isdigit() or not port or not port.isdigit():
            return None
        if int(port) <= 0:
            return None
        return f"{proto}/{int(port)}"

    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    if field == "dstport":
        if not text.isdigit():
            return None
        port_num = int(text)
        if port_num <= 0:
            return None
        return str(port_num)

    if text == "0":
        return None

    return text


def _build_policy_filter(policy_id: int, action: str | None = None) -> str:
    """Build a policy filter for one policy ID."""
    parts = [f"policyid=={policy_id}"]
    if action:
        parts.append(f"action=={sanitize_filter_value(action)}")
    return " and ".join(parts)


def _build_port_range_filter(low: int, high: int) -> str:
    """Build a dstport filter for a single port or inclusive range."""
    if low == high:
        return f"dstport=={low}"
    return f"dstport>={low} and dstport<={high}"


def _build_protocol_range_filter(low: int, high: int) -> str:
    """Build a proto filter for a single IP protocol or inclusive range."""
    if low == high:
        return f"proto=={low}"
    return f"proto>={low} and proto<={high}"


def _build_residual_port_ranges(
    excluded_ports: list[int],
    low: int = 1,
    high: int = 65535,
) -> list[tuple[int, int]]:
    """Build non-overlapping port ranges excluding known ports."""
    ranges: list[tuple[int, int]] = []
    cursor = low
    for port in sorted({port for port in excluded_ports if low <= port <= high}):
        if cursor <= port - 1:
            ranges.append((cursor, port - 1))
        cursor = port + 1
    if cursor <= high:
        ranges.append((cursor, high))
    return ranges


async def _run_log_count(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter_str: str | None,
    timeout: int,
    retries: int = 3,
) -> int:
    """Run a log search and return the exact matched log count."""
    last_error: Exception | None = None

    for attempt in range(retries):
        tid: int | None = None
        client = None
        try:
            client = await _get_connected_client()
            start_result = await client.logsearch_start(
                adom=adom,
                logtype="traffic",
                device=device_filter,
                time_range=time_range,
                filter=filter_str,
                limit=1,
                offset=0,
            )
            tid = start_result.get("tid")
            if not tid:
                raise RuntimeError(f"No TID returned for count query: {start_result}")

            started = time.monotonic()
            while True:
                if time.monotonic() - started > timeout:
                    raise TimeoutError(
                        f"Count query timed out after {timeout}s for filter {filter_str}"
                    )

                result = await client.logsearch_count(adom, tid)
                if result.get("progress-percent", 0) >= 100:
                    return int(result.get("matched-logs", 0))

                await asyncio.sleep(POLL_INTERVAL)
        except RETRYABLE_QUERY_EXCEPTIONS as exc:
            last_error = exc
            if attempt + 1 < retries:
                await asyncio.sleep(POLL_INTERVAL)
        finally:
            if tid and client is not None:
                try:
                    await client.logsearch_cancel(adom, tid)
                except RETRYABLE_QUERY_EXCEPTIONS:
                    pass

    raise RuntimeError(f"Count query failed for filter {filter_str}: {last_error}")


async def _run_log_count_resilient(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter_str: str | None,
    timeout: int,
    stats: dict[str, int] | None = None,
    min_split_hours: int = DEFAULT_EXACT_MIN_SPLIT_HOURS,
) -> int:
    """Run an exact count query, splitting the time range if needed."""
    if stats is not None:
        stats["count_attempts"] = stats.get("count_attempts", 0) + 1

    try:
        return await _run_log_count(
            adom=adom,
            device_filter=device_filter,
            time_range=time_range,
            filter_str=filter_str,
            timeout=timeout,
        )
    except RETRYABLE_QUERY_EXCEPTIONS:
        start, end = _parse_time_range_dict(time_range)
        span = end - start
        if span <= timedelta(hours=max(min_split_hours, 1)):
            raise

        split_ranges = _split_time_range_non_overlapping(time_range)
        if not split_ranges:
            raise
        left_range, right_range = split_ranges

        if stats is not None:
            stats["fallback_splits"] = stats.get("fallback_splits", 0) + 1

        left_hits = await _run_log_count_resilient(
            adom=adom,
            device_filter=device_filter,
            time_range=left_range,
            filter_str=filter_str,
            timeout=timeout,
            stats=stats,
            min_split_hours=min_split_hours,
        )
        right_hits = await _run_log_count_resilient(
            adom=adom,
            device_filter=device_filter,
            time_range=right_range,
            filter_str=filter_str,
            timeout=timeout,
            stats=stats,
            min_split_hours=min_split_hours,
        )
        return left_hits + right_hits


async def _run_log_count_over_slices(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_slices: list[dict[str, str]],
    filter_str: str | None,
    timeout: int,
    stats: dict[str, int] | None = None,
) -> int:
    """Run exact counts over a fixed slice partition and sum the results."""
    total = 0
    for time_slice in time_slices:
        if stats is not None:
            stats["count_attempts"] = stats.get("count_attempts", 0) + 1
        total += await _run_log_count(
            adom=adom,
            device_filter=device_filter,
            time_range=time_slice,
            filter_str=filter_str,
            timeout=timeout,
        )
    return total


async def _run_log_count_exact(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter_str: str | None,
    timeout: int,
    stats: dict[str, int] | None = None,
    slice_day_candidates: list[int] | None = None,
    min_split_hours: int = DEFAULT_EXACT_MIN_SPLIT_HOURS,
) -> int:
    """Run an exact count using progressively smaller fixed slice partitions."""
    candidates = slice_day_candidates or [1]
    last_error: Exception | None = None

    for slice_days in candidates:
        try:
            return await _run_log_count_over_slices(
                adom=adom,
                device_filter=device_filter,
                time_slices=_build_exact_time_slices(time_range, slice_days),
                filter_str=filter_str,
                timeout=timeout,
                stats=stats,
            )
        except RETRYABLE_QUERY_EXCEPTIONS as exc:
            last_error = exc

    if last_error is not None:
        return await _run_log_count_resilient(
            adom=adom,
            device_filter=device_filter,
            time_range=time_range,
            filter_str=filter_str,
            timeout=timeout,
            stats=stats,
            min_split_hours=min_split_hours,
        )

    raise RuntimeError(f"Count query failed for filter {filter_str}")


async def _run_log_sample(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter_str: str | None,
    limit: int,
    offset: int,
    timeout: int,
    retries: int = 2,
) -> list[dict[str, Any]]:
    """Run a bounded log query and return sampled log rows."""
    last_error: Exception | None = None

    for attempt in range(retries):
        tid: int | None = None
        client = None
        try:
            client = await _get_connected_client()
            start_result = await client.logsearch_start(
                adom=adom,
                logtype="traffic",
                device=device_filter,
                time_range=time_range,
                filter=filter_str,
                limit=limit,
                offset=offset,
            )
            tid = start_result.get("tid")
            if not tid:
                raise RuntimeError(f"No TID returned for sample query: {start_result}")

            started = time.monotonic()
            while True:
                if time.monotonic() - started > timeout:
                    raise TimeoutError(
                        f"Sample query timed out after {timeout}s for filter {filter_str}"
                    )

                result = await client.logsearch_fetch(
                    adom=adom,
                    tid=tid,
                    limit=limit,
                    offset=offset,
                )
                if result.get("percentage", 0) >= 100:
                    rows = result.get("data", [])
                    if not isinstance(rows, list):
                        rows = [rows] if rows else []
                    return rows

                await asyncio.sleep(POLL_INTERVAL)
        except RETRYABLE_QUERY_EXCEPTIONS as exc:
            last_error = exc
            if attempt + 1 < retries:
                await asyncio.sleep(POLL_INTERVAL)
        finally:
            if tid and client is not None:
                try:
                    await client.logsearch_cancel(adom, tid)
                except RETRYABLE_QUERY_EXCEPTIONS:
                    pass

    logger.warning(f"Sample query failed for filter {filter_str}: {last_error}")
    return []


def _normalize_logsearch_rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalize one logsearch fetch payload into a list of log rows."""
    rows = result.get("data", [])
    if not isinstance(rows, list):
        rows = [rows] if rows else []
    return [row for row in rows if isinstance(row, dict)]


def _is_invalid_tid_error(exc: Exception) -> bool:
    """Return True when a logsearch failure indicates the server discarded the task."""
    return "invalid tid" in str(exc).lower()


def _should_split_exact_fetch_error(exc: Exception) -> bool:
    """Return True when an exact-fetch failure should move to a smaller time slice."""
    message = str(exc).lower()
    return (
        _is_invalid_tid_error(exc)
        or isinstance(exc, (TimeoutError, FazTimeoutError))
        or "timed out" in message
        or "timeout" in message
    )


async def _run_log_fetch_all(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter_str: str | None,
    timeout: int,
    consumer: Callable[[list[dict[str, Any]]], None],
    page_size: int = DEFAULT_EXACT_FETCH_PAGE_SIZE,
    retries: int = 2,
) -> int:
    """Run one full log search and stream every matching row exactly."""
    last_error: Exception | None = None
    page_size = max(1, min(page_size, DEFAULT_EXACT_FETCH_PAGE_SIZE))

    for attempt in range(retries):
        tid: int | None = None
        client = None
        try:
            staged_pages: list[list[dict[str, Any]]] = []
            client = await _get_connected_client()
            start_result = await client.logsearch_start(
                adom=adom,
                logtype="traffic",
                device=device_filter,
                time_range=time_range,
                filter=filter_str,
                limit=page_size,
                offset=0,
            )
            tid = start_result.get("tid")
            if not tid:
                raise RuntimeError(f"No TID returned for exact fetch query: {start_result}")

            started = time.monotonic()
            while True:
                if time.monotonic() - started > timeout:
                    raise TimeoutError(
                        f"Exact fetch timed out after {timeout}s for filter {filter_str}"
                    )

                first_page = await client.logsearch_fetch(
                    adom=adom,
                    tid=tid,
                    limit=page_size,
                    offset=0,
                )
                if first_page.get("percentage", 0) >= 100:
                    rows = _normalize_logsearch_rows(first_page)
                    total_count_raw = first_page.get("total-count")
                    expected_total = (
                        int(total_count_raw) if total_count_raw is not None else None
                    )
                    processed_rows = 0

                    if rows:
                        staged_pages.append(rows)
                        processed_rows += len(rows)

                    offset = len(rows)
                    while True:
                        if expected_total is not None and offset >= expected_total:
                            break
                        if time.monotonic() - started > timeout:
                            raise TimeoutError(
                                f"Exact fetch paging timed out after {timeout}s for filter {filter_str}"
                            )

                        page = await client.logsearch_fetch(
                            adom=adom,
                            tid=tid,
                            limit=page_size,
                            offset=offset,
                        )
                        if page.get("percentage", 0) < 100:
                            await asyncio.sleep(POLL_INTERVAL)
                            continue

                        page_rows = _normalize_logsearch_rows(page)
                        if not page_rows:
                            break

                        staged_pages.append(page_rows)
                        processed_rows += len(page_rows)
                        offset += len(page_rows)
                        if expected_total is None and len(page_rows) < page_size:
                            break

                    if expected_total is not None and processed_rows < expected_total:
                        raise RuntimeError(
                            f"Incomplete exact fetch for filter {filter_str}: "
                            f"expected {expected_total} rows, got {processed_rows}"
                        )
                    for page_rows in staged_pages:
                        consumer(page_rows)
                    return expected_total if expected_total is not None else processed_rows

                await asyncio.sleep(POLL_INTERVAL)
        except RETRYABLE_QUERY_EXCEPTIONS as exc:
            last_error = exc
            if _should_split_exact_fetch_error(exc):
                break
            if attempt + 1 < retries:
                await asyncio.sleep(POLL_INTERVAL)
        finally:
            if tid and client is not None:
                try:
                    await client.logsearch_cancel(adom, tid)
                except RETRYABLE_QUERY_EXCEPTIONS:
                    pass

    raise RuntimeError(f"Exact fetch failed for filter {filter_str}: {last_error}")


async def _run_log_fetch_resilient(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter_str: str | None,
    timeout: int,
    consumer: Callable[[list[dict[str, Any]]], None],
    min_split_minutes: int = DEFAULT_PORT_ANALYSIS_MIN_RETRY_SPLIT_MINUTES,
) -> int:
    """Run a full exact fetch, splitting the time range when one query is too slow."""
    try:
        return await _run_log_fetch_all(
            adom=adom,
            device_filter=device_filter,
            time_range=time_range,
            filter_str=filter_str,
            timeout=timeout,
            consumer=consumer,
        )
    except RETRYABLE_QUERY_EXCEPTIONS:
        start, end = _parse_time_range_dict(time_range)
        span = end - start
        logger.info(
            "Exact fetch for %s over %s failed; splitting below %d minutes",
            filter_str or "<none>",
            _format_span_label(span),
            max(min_split_minutes, 1),
        )
        if span <= timedelta(minutes=max(min_split_minutes, 1)):
            raise

        split_ranges = _split_time_range_non_overlapping(time_range)
        if not split_ranges:
            raise
        left_range, right_range = split_ranges
        left_rows = await _run_log_fetch_resilient(
            adom=adom,
            device_filter=device_filter,
            time_range=left_range,
            filter_str=filter_str,
            timeout=timeout,
            consumer=consumer,
            min_split_minutes=min_split_minutes,
        )
        right_rows = await _run_log_fetch_resilient(
            adom=adom,
            device_filter=device_filter,
            time_range=right_range,
            filter_str=filter_str,
            timeout=timeout,
            consumer=consumer,
            min_split_minutes=min_split_minutes,
        )
        return left_rows + right_rows


async def _run_log_fetch_exact(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter_str: str | None,
    timeout: int,
    slice_minutes: int,
    consumer: Callable[[list[dict[str, Any]]], None],
) -> int:
    """Fetch every matching log row exactly, streaming rows into a consumer."""
    time_slices = _build_exact_time_slices_minutes(time_range, slice_minutes)
    semaphore = asyncio.Semaphore(max(DEFAULT_PORT_ANALYSIS_SLICE_CONCURRENCY, 1))

    async def fetch_time_slice(time_slice: dict[str, str]) -> int:
        async with semaphore:
            return await _run_log_fetch_resilient(
                adom=adom,
                device_filter=device_filter,
                time_range=time_slice,
                filter_str=filter_str,
                timeout=timeout,
                consumer=consumer,
                min_split_minutes=DEFAULT_PORT_ANALYSIS_MIN_RETRY_SPLIT_MINUTES,
            )

    slice_totals = await asyncio.gather(*(fetch_time_slice(time_slice) for time_slice in time_slices))
    return sum(slice_totals)


async def _collect_port_analysis_slice_accumulator(
    *,
    policy_id: int,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    action: str | None,
    filter_str: str,
    timeout: int,
    progress_callback: PortAnalysisProgressCallback | None = None,
    min_split_minutes: int = DEFAULT_PORT_ANALYSIS_MIN_RETRY_SPLIT_MINUTES,
) -> PortAnalysisAccumulator:
    """Collect one exact policy/time slice, reusing or populating persistent cache."""
    cached = _load_cached_port_analysis_accumulator_recursive(
        adom=adom,
        device_filter=device_filter,
        policy_id=policy_id,
        action=action,
        time_range=time_range,
        min_split_minutes=min_split_minutes,
    )
    if cached is not None:
        await _emit_port_analysis_progress(
            progress_callback,
            "slice_cached",
            {
                "policy_id": policy_id,
                "time_range": time_range,
                "hits": cached.total_hits,
            },
        )
        return cached

    accumulator = PortAnalysisAccumulator()
    try:
        await _run_log_fetch_all(
            adom=adom,
            device_filter=device_filter,
            time_range=time_range,
            filter_str=filter_str,
            timeout=timeout,
            consumer=accumulator.consume_rows,
        )
    except RETRYABLE_QUERY_EXCEPTIONS as exc:
        if not _should_split_exact_fetch_error(exc):
            raise

        start, end = _parse_time_range_dict(time_range)
        span = end - start
        if span <= timedelta(minutes=max(min_split_minutes, 1)):
            raise

        split_ranges = _split_time_range_non_overlapping(time_range)
        if not split_ranges:
            raise
        left_range, right_range = split_ranges

        await _emit_port_analysis_progress(
            progress_callback,
            "slice_split",
            {
                "policy_id": policy_id,
                "time_range": time_range,
                "reason": str(exc),
            },
        )

        left_accumulator = await _collect_port_analysis_slice_accumulator(
            policy_id=policy_id,
            adom=adom,
            device_filter=device_filter,
            time_range=left_range,
            action=action,
            filter_str=filter_str,
            timeout=timeout,
            progress_callback=progress_callback,
            min_split_minutes=min_split_minutes,
        )
        right_accumulator = await _collect_port_analysis_slice_accumulator(
            policy_id=policy_id,
            adom=adom,
            device_filter=device_filter,
            time_range=right_range,
            action=action,
            filter_str=filter_str,
            timeout=timeout,
            progress_callback=progress_callback,
            min_split_minutes=min_split_minutes,
        )
        accumulator.merge(left_accumulator)
        accumulator.merge(right_accumulator)
    _store_cached_port_analysis_accumulator(
        adom=adom,
        device_filter=device_filter,
        policy_id=policy_id,
        action=action,
        time_range=time_range,
        accumulator=accumulator,
    )
    await _emit_port_analysis_progress(
        progress_callback,
        "slice_computed",
        {
            "policy_id": policy_id,
            "time_range": time_range,
            "hits": accumulator.total_hits,
        },
    )
    return accumulator


async def _run_cached_port_analysis_exact(
    *,
    policy_id: int,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    action: str | None,
    filter_str: str,
    timeout: int,
    slice_minutes: int,
    progress_callback: PortAnalysisProgressCallback | None = None,
    min_split_minutes: int = DEFAULT_PORT_ANALYSIS_MIN_RETRY_SPLIT_MINUTES,
) -> PortAnalysisAccumulator:
    """Execute exact port analysis with persistent slice cache and exact merging."""
    cached = _load_cached_port_analysis_accumulator(
        adom=adom,
        device_filter=device_filter,
        policy_id=policy_id,
        action=action,
        time_range=time_range,
    )
    if cached is not None:
        await _emit_port_analysis_progress(
            progress_callback,
            "slice_cached",
            {
                "policy_id": policy_id,
                "time_range": time_range,
                "hits": cached.total_hits,
            },
        )
        return cached

    time_slices = _build_exact_time_slices_minutes(time_range, slice_minutes)
    await _emit_port_analysis_progress(
        progress_callback,
        "slices_planned",
        {
            "policy_id": policy_id,
            "count": len(time_slices),
            "time_range": time_range,
        },
    )
    semaphore = asyncio.Semaphore(max(DEFAULT_PORT_ANALYSIS_SLICE_CONCURRENCY, 1))

    async def fetch_time_slice(time_slice: dict[str, str]) -> PortAnalysisAccumulator:
        async with semaphore:
            return await _collect_port_analysis_slice_accumulator(
                policy_id=policy_id,
                adom=adom,
                device_filter=device_filter,
                time_range=time_slice,
                action=action,
                filter_str=filter_str,
                timeout=timeout,
                progress_callback=progress_callback,
                min_split_minutes=min_split_minutes,
            )

    slice_accumulators = await asyncio.gather(
        *(fetch_time_slice(time_slice) for time_slice in time_slices)
    )

    accumulator = PortAnalysisAccumulator()
    for slice_accumulator in slice_accumulators:
        accumulator.merge(slice_accumulator)

    if len(time_slices) > 1:
        _store_cached_port_analysis_accumulator(
            adom=adom,
            device_filter=device_filter,
            policy_id=policy_id,
            action=action,
            time_range=time_range,
            accumulator=accumulator,
        )

    return accumulator


async def _discover_policy_candidates(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    policy_filter: str,
    time_range: str,
    slice_days: int,
    sample_limit: int,
    timeout: int,
    fields: tuple[str, ...],
) -> tuple[dict[str, Counter[str]], dict[str, Any]]:
    """Sample logs across time slices to discover candidate values."""
    start, end = _parse_time_range_bounds(time_range)
    requested_slices = _estimate_slice_count(start, end, slice_days)
    slices = _build_time_slices(time_range, slice_days)
    base_offsets = [0, sample_limit] if len(slices) == 1 else [0]
    discovery_filters: list[DiscoveryQueryShape] = [
        {"name": "base", "extra_filter": None, "offsets": base_offsets}
    ]
    if "port_pair" in fields or "dstport" in fields:
        discovery_filters.extend(
            [
                {"name": "low-port", "extra_filter": "dstport<1024", "offsets": [0]},
                {
                    "name": "mid-port",
                    "extra_filter": "dstport>=1024 and dstport<=10000",
                    "offsets": [0],
                },
            ]
        )

    counters: dict[str, Counter[str]] = {field: Counter() for field in fields}
    discovery: dict[str, Any] = {
        "requested_slices": requested_slices,
        "slices_scanned": 0,
        "adaptive_sampling": len(slices) < requested_slices,
        "queries_attempted": 0,
        "sampled_logs": 0,
        "errors": [],
    }

    for time_slice in slices:
        discovery["slices_scanned"] += 1
        for query_shape in discovery_filters:
            filter_str = _combine_filters(policy_filter, query_shape["extra_filter"])
            for offset in query_shape["offsets"]:
                discovery["queries_attempted"] += 1
                rows = await _run_log_sample(
                    adom=adom,
                    device_filter=device_filter,
                    time_range=time_slice,
                    filter_str=filter_str,
                    limit=sample_limit,
                    offset=offset,
                    timeout=timeout,
                )

                if not rows:
                    continue

                discovery["sampled_logs"] += len(rows)
                for row in rows:
                    for counter_field in counters:
                        normalized = _normalize_sample_value(
                            counter_field,
                            row.get(counter_field),
                            row,
                        )
                        if normalized:
                            counters[counter_field][normalized] += 1

    discovery["discovered_candidates"] = {
        field: len(counter) for field, counter in counters.items()
    }
    return counters, discovery


async def _discover_protocol_candidates(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    policy_filter: str,
    time_range: str,
    sample_limit: int,
    timeout: int,
) -> Counter[str]:
    """Sample logs across the time range to discover active IP protocols."""
    slices = _build_time_slices(time_range, slice_days=1)
    offsets = [0, sample_limit] if len(slices) == 1 else [0]
    protocols: Counter[str] = Counter()

    for time_slice in slices:
        for offset in offsets:
            rows = await _run_log_sample(
                adom=adom,
                device_filter=device_filter,
                time_range=time_slice,
                filter_str=policy_filter,
                limit=sample_limit,
                offset=offset,
                timeout=timeout,
            )
            for row in rows:
                proto = str(row.get("proto", "")).strip()
                if proto.isdigit():
                    protocols[str(int(proto))] += 1

    return protocols


def _build_discovered_value_filter(field: str, value: str) -> str:
    """Build a filter for a discovered candidate value."""
    if field == "port_pair":
        proto, port = value.split("/", maxsplit=1)
        return _combine_filters(f"proto=={proto}", f"dstport=={port}") or ""
    return f"{field}=={sanitize_filter_value(value)}"


async def _count_discovered_values(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    base_filter: str,
    field: str,
    counter: Counter[str],
    candidate_limit: int,
    timeout: int,
    result_key: str,
    slice_day_candidates: list[int] | None = None,
    concurrency: int = 1,
) -> tuple[list[dict[str, Any]], list[CountError], int]:
    """Count exact hits for the strongest discovered candidates."""
    ranked: list[dict[str, Any]] = []
    errors: list[CountError] = []
    semaphore = asyncio.Semaphore(max(concurrency, 1))

    async def count_value(value: str) -> tuple[str, int | None, str | None]:
        field_filter = _build_discovered_value_filter(field, value)
        try:
            async with semaphore:
                hits = await _run_log_count_exact(
                    adom=adom,
                    device_filter=device_filter,
                    time_range=time_range,
                    filter_str=_combine_filters(base_filter, field_filter),
                    timeout=timeout,
                    slice_day_candidates=slice_day_candidates,
                )
        except RETRYABLE_QUERY_EXCEPTIONS as exc:
            return value, None, str(exc)
        return value, hits, None

    results = await asyncio.gather(
        *(count_value(value) for value, _sample_hits in counter.most_common(candidate_limit))
    )

    for value, hits, error in results:
        if error is not None:
            errors.append({"field": field, "value": value, "message": error})
            continue
        if hits and hits > 0:
            ranked.append({result_key: value, "hits": hits})

    ranked.sort(key=lambda item: (-int(item["hits"]), str(item[result_key])))
    return ranked, errors, sum(int(item["hits"]) for item in ranked)


def _build_empty_policy_profile_result(policy_id: int) -> dict[str, Any]:
    """Build a successful empty sampled-profile result."""
    return {
        "policy_id": policy_id,
        "total_hits": 0,
        "top_ports": [],
        "top_ports_residual": 0,
        "top_services": [],
        "top_services_residual": 0,
        "top_applications": [],
        "top_applications_residual": 0,
    }


def _build_empty_port_analysis_result(policy_id: int) -> dict[str, Any]:
    """Build a successful empty exact-analysis result."""
    return {
        "policy_id": policy_id,
        "total_hits": 0,
        "is_exact": True,
        "ports": [],
        "protocols": [],
        "portless_protocols": [],
        "uncovered_port_hits": 0,
        "icmp": [],
    }


def _protocol_sort_key(protocol: str) -> tuple[int, int, str]:
    """Sort protocol identifiers numerically, with unknown values last."""
    if protocol.isdigit():
        return (0, int(protocol), protocol)
    return (1, 0, protocol)


def _port_pair_sort_key(port_pair: str) -> tuple[float, float, str]:
    """Sort proto/port keys numerically when possible."""
    try:
        proto, port = port_pair.split("/", maxsplit=1)
        return (int(proto), int(port), port_pair)
    except ValueError:
        return (math.inf, math.inf, port_pair)


def _format_protocol_name(protocol: str) -> str:
    """Map a protocol identifier to a display name."""
    if protocol.isdigit():
        proto_int = int(protocol)
        return PROTOCOL_NAMES.get(proto_int, f"other({protocol})")
    return f"other({protocol})"


def _format_protocol_summary_name(protocol: str) -> str:
    """Map protocol buckets to protocol-summary labels."""
    if protocol == "other":
        return "other"
    return _format_protocol_name(protocol)


def _format_icmp_type_code(service: str) -> str:
    """Map a FAZ ICMP service string to a stable summary key."""
    if service.upper() == "PING":
        return "type=8/code=0"
    if service.startswith("icmp/"):
        parts = service.split("/")
        if len(parts) == 3:
            return f"type={parts[1]}/code={parts[2]}"
    return f"service={service}"


def _collapse_count_errors(errors: list[CountError], policy_id: int) -> None:
    """Raise a readable error for candidate recount failures."""
    if not errors:
        return
    first = errors[0]
    raise RuntimeError(
        f"Policy {policy_id} recount failed for {first['field']}={first['value']}: "
        f"{first['message']}"
    )


async def _count_filters_bounded(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filters: dict[str, str],
    timeout: int,
    slice_day_candidates: list[int] | None = None,
    stats: dict[str, int] | None = None,
    concurrency: int = 1,
) -> dict[str, int]:
    """Run multiple exact-count filters with bounded intra-policy concurrency."""
    if not filters:
        return {}

    semaphore = asyncio.Semaphore(max(concurrency, 1))

    async def count_one(key: str, filter_str: str) -> tuple[str, int]:
        async with semaphore:
            hits = await _run_log_count_exact(
                adom=adom,
                device_filter=device_filter,
                time_range=time_range,
                filter_str=filter_str,
                timeout=timeout,
                stats=stats,
                slice_day_candidates=slice_day_candidates,
            )
        return key, hits

    pairs = await asyncio.gather(
        *(count_one(key, filter_str) for key, filter_str in filters.items())
    )
    return dict(pairs)


def _select_protocols_to_count(
    sampled_protocols: Counter[str],
    base_protocols: tuple[int, ...],
) -> list[str]:
    """Select a bounded set of protocols to exact-count for one policy."""
    selected_protocols = {str(protocol) for protocol in base_protocols}
    for protocol, _sample_hits in sampled_protocols.most_common(DEFAULT_DISCOVERED_PROTOCOL_LIMIT):
        selected_protocols.add(protocol)
    return sorted(selected_protocols, key=_protocol_sort_key)


async def _collect_protocol_buckets(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    base_filter: str,
    base_protocols: tuple[int, ...],
    total_hits: int,
    timeout: int,
    sampled_protocols: Counter[str] | None = None,
    sampled_time_range: str | None = None,
    slice_day_candidates: list[int] | None = None,
    stats: dict[str, int] | None = None,
) -> tuple[dict[str, int], int]:
    """Collect exact counts for sampled protocol buckets plus a residual `other` bucket."""
    if sampled_protocols is None:
        if sampled_time_range is None:
            raise RuntimeError("sampled_time_range is required when sampled_protocols is not provided")
        sampled_protocols = await _discover_protocol_candidates(
            adom=adom,
            device_filter=device_filter,
            policy_filter=base_filter,
            time_range=sampled_time_range,
            sample_limit=DEFAULT_POLICY_SAMPLE_LIMIT,
            timeout=min(timeout, DEFAULT_SEARCH_TIMEOUT),
        )

    filters = {
        protocol: _combine_filters(base_filter, f"proto=={protocol}") or ""
        for protocol in _select_protocols_to_count(sampled_protocols, base_protocols)
    }
    semaphore = asyncio.Semaphore(DEFAULT_PROTOCOL_COUNT_CONCURRENCY)

    async def count_one(protocol: str, filter_str: str) -> tuple[str, int | None, str | None]:
        try:
            async with semaphore:
                hits = await _run_log_count_exact(
                    adom=adom,
                    device_filter=device_filter,
                    time_range=time_range,
                    filter_str=filter_str,
                    timeout=timeout,
                    stats=stats,
                    slice_day_candidates=slice_day_candidates,
                )
        except RETRYABLE_QUERY_EXCEPTIONS as exc:
            return protocol, None, str(exc)
        return protocol, hits, None

    results = await asyncio.gather(
        *(count_one(protocol, filter_str) for protocol, filter_str in filters.items())
    )

    exact_hits: dict[str, int] = {}
    failed_protocols: list[str] = []
    for protocol, hits, error in results:
        if error is not None:
            failed_protocols.append(protocol)
            continue
        if hits is not None:
            exact_hits[protocol] = hits

    if failed_protocols:
        logger.warning(
            "Protocol recount timed out for %d protocol buckets on filter %s",
            len(failed_protocols),
            base_filter,
        )

    exact_total = sum(exact_hits.values())
    return exact_hits, max(total_hits - exact_total, 0)


async def _enumerate_exact_ports(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    slice_day_candidates: list[int] | None,
    base_filter: str,
    low: int,
    high: int,
    known_hits: int,
    timeout: int,
    stats: dict[str, int] | None = None,
    min_split_hours: int = DEFAULT_EXACT_MIN_SPLIT_HOURS,
) -> list[PortHit]:
    """Enumerate exact destination ports using recursive range counts."""
    if known_hits <= 0:
        return []

    if low == high:
        return [{"port": str(low), "hits": known_hits}]

    mid = (low + high) // 2
    if stats is not None:
        stats["count_queries"] = stats.get("count_queries", 0) + 1
    left_filter = _combine_filters(base_filter, _build_port_range_filter(low, mid))
    left_hits = await _run_log_count_exact(
        adom=adom,
        device_filter=device_filter,
        time_range=time_range,
        filter_str=left_filter,
        timeout=timeout,
        stats=stats,
        slice_day_candidates=slice_day_candidates,
        min_split_hours=min_split_hours,
    )
    right_hits = max(known_hits - left_hits, 0)

    left_results = await _enumerate_exact_ports(
        adom=adom,
        device_filter=device_filter,
        time_range=time_range,
        slice_day_candidates=slice_day_candidates,
        base_filter=base_filter,
        low=low,
        high=mid,
        known_hits=left_hits,
        timeout=timeout,
        stats=stats,
        min_split_hours=min_split_hours,
    )
    right_results = await _enumerate_exact_ports(
        adom=adom,
        device_filter=device_filter,
        time_range=time_range,
        slice_day_candidates=slice_day_candidates,
        base_filter=base_filter,
        low=mid + 1,
        high=high,
        known_hits=right_hits,
        timeout=timeout,
        stats=stats,
        min_split_hours=min_split_hours,
    )
    return left_results + right_results


async def _enumerate_exact_protocols(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    slice_day_candidates: list[int] | None,
    base_filter: str,
    low: int,
    high: int,
    known_hits: int,
    timeout: int,
    stats: dict[str, int] | None = None,
    min_split_hours: int = DEFAULT_EXACT_MIN_SPLIT_HOURS,
) -> list[ProtocolHit]:
    """Enumerate exact IP protocols using recursive range counts."""
    if known_hits <= 0:
        return []

    if low == high:
        return [{"protocol": str(low), "hits": known_hits}]

    mid = (low + high) // 2
    if stats is not None:
        stats["protocol_range_queries"] = stats.get("protocol_range_queries", 0) + 1
    left_filter = _combine_filters(base_filter, _build_protocol_range_filter(low, mid))
    left_hits = await _run_log_count_exact(
        adom=adom,
        device_filter=device_filter,
        time_range=time_range,
        filter_str=left_filter,
        timeout=timeout,
        stats=stats,
        slice_day_candidates=slice_day_candidates,
        min_split_hours=min_split_hours,
    )
    right_hits = max(known_hits - left_hits, 0)

    left_results = await _enumerate_exact_protocols(
        adom=adom,
        device_filter=device_filter,
        time_range=time_range,
        slice_day_candidates=slice_day_candidates,
        base_filter=base_filter,
        low=low,
        high=mid,
        known_hits=left_hits,
        timeout=timeout,
        stats=stats,
        min_split_hours=min_split_hours,
    )
    right_results = await _enumerate_exact_protocols(
        adom=adom,
        device_filter=device_filter,
        time_range=time_range,
        slice_day_candidates=slice_day_candidates,
        base_filter=base_filter,
        low=mid + 1,
        high=high,
        known_hits=right_hits,
        timeout=timeout,
        stats=stats,
        min_split_hours=min_split_hours,
    )
    return left_results + right_results


async def _build_icmp_breakdown(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: str,
    full_time_range: dict[str, str],
    base_filter: str,
    icmp_hits: int,
    timeout: int,
    slice_day_candidates: list[int],
) -> list[ICMPTypeHit]:
    """Build a FAZ-aware ICMP breakdown from service values."""
    if icmp_hits <= 0:
        return []

    icmp_filter = _combine_filters(base_filter, "proto==1")
    candidates, _discovery = await _discover_policy_candidates(
        adom=adom,
        device_filter=device_filter,
        policy_filter=icmp_filter or "",
        time_range=time_range,
        slice_days=1,
        sample_limit=DEFAULT_POLICY_SAMPLE_LIMIT,
        timeout=min(timeout, DEFAULT_SEARCH_TIMEOUT),
        fields=("service",),
    )

    exact_items, errors, exact_total = await _count_discovered_values(
        adom=adom,
        device_filter=device_filter,
        time_range=full_time_range,
        base_filter=icmp_filter or "",
        field="service",
        counter=candidates["service"],
        candidate_limit=DEFAULT_POLICY_CANDIDATE_LIMIT,
        timeout=timeout,
        result_key="service",
        slice_day_candidates=slice_day_candidates,
        concurrency=DEFAULT_VALUE_RECOUNT_CONCURRENCY,
    )
    if errors:
        logger.warning("ICMP breakdown recount had %d errors; preserving totals with residual", len(errors))

    breakdown: dict[str, int] = {}
    for item in exact_items:
        label = _format_icmp_type_code(str(item["service"]))
        breakdown[label] = breakdown.get(label, 0) + int(item["hits"])

    residual = max(icmp_hits - exact_total, 0)
    if residual > 0:
        breakdown["other"] = breakdown.get("other", 0) + residual

    return sorted(
        [{"type_code": label, "hits": hits} for label, hits in breakdown.items()],
        key=lambda item: (-int(item["hits"]), str(item["type_code"])),
    )


async def _build_policy_traffic_profile_result(
    *,
    policy_id: int,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: str,
    full_time_range: dict[str, str],
    action: str | None,
    top_n: int,
    slice_day_candidates: list[int],
    discovery_slice_days: int,
) -> dict[str, Any]:
    """Build the sampled traffic profile result for one policy."""
    base_filter = _build_policy_filter(policy_id, action)
    total_hits = await _run_log_count_exact(
        adom=adom,
        device_filter=device_filter,
        time_range=full_time_range,
        filter_str=base_filter,
        timeout=DEFAULT_POLICY_PROFILE_TIMEOUT,
        slice_day_candidates=slice_day_candidates,
    )
    if total_hits == 0:
        return _build_empty_policy_profile_result(policy_id)

    candidate_counters, _discovery = await _discover_policy_candidates(
        adom=adom,
        device_filter=device_filter,
        policy_filter=base_filter,
        time_range=time_range,
        slice_days=discovery_slice_days,
        sample_limit=DEFAULT_POLICY_SAMPLE_LIMIT,
        timeout=min(DEFAULT_POLICY_PROFILE_TIMEOUT, DEFAULT_SEARCH_TIMEOUT),
        fields=("port_pair", "service", "app"),
    )

    candidate_limit = max(DEFAULT_POLICY_CANDIDATE_LIMIT, top_n)
    (
        (ports, port_errors, ports_total),
        (services, service_errors, services_total),
        (applications, app_errors, applications_total),
    ) = await asyncio.gather(
        _count_discovered_values(
            adom=adom,
            device_filter=device_filter,
            time_range=full_time_range,
            base_filter=base_filter,
            field="port_pair",
            counter=candidate_counters["port_pair"],
            candidate_limit=candidate_limit,
            timeout=DEFAULT_POLICY_PROFILE_TIMEOUT,
            result_key="port",
            slice_day_candidates=slice_day_candidates,
            concurrency=DEFAULT_VALUE_RECOUNT_CONCURRENCY,
        ),
        _count_discovered_values(
            adom=adom,
            device_filter=device_filter,
            time_range=full_time_range,
            base_filter=base_filter,
            field="service",
            counter=candidate_counters["service"],
            candidate_limit=candidate_limit,
            timeout=DEFAULT_POLICY_PROFILE_TIMEOUT,
            result_key="service",
            slice_day_candidates=slice_day_candidates,
            concurrency=DEFAULT_VALUE_RECOUNT_CONCURRENCY,
        ),
        _count_discovered_values(
            adom=adom,
            device_filter=device_filter,
            time_range=full_time_range,
            base_filter=base_filter,
            field="app",
            counter=candidate_counters["app"],
            candidate_limit=candidate_limit,
            timeout=DEFAULT_POLICY_PROFILE_TIMEOUT,
            result_key="application",
            slice_day_candidates=slice_day_candidates,
            concurrency=DEFAULT_VALUE_RECOUNT_CONCURRENCY,
        ),
    )

    _collapse_count_errors(port_errors + service_errors + app_errors, policy_id)

    return {
        "policy_id": policy_id,
        "total_hits": total_hits,
        "top_ports": sorted(
            ports[:top_n],
            key=lambda item: (-int(item["hits"]), _port_pair_sort_key(str(item["port"]))),
        ),
        "top_ports_residual": max(total_hits - ports_total, 0),
        "top_services": services[:top_n],
        "top_services_residual": max(total_hits - services_total, 0),
        "top_applications": applications[:top_n],
        "top_applications_residual": max(total_hits - applications_total, 0),
    }


async def _build_policy_port_analysis_result(
    *,
    policy_id: int,
    adom: str,
    device_filter: list[dict[str, str]],
    full_time_range: dict[str, str],
    action: str | None,
    slice_minutes: int,
    fetch_timeout: int = DEFAULT_PORT_ANALYSIS_FETCH_TIMEOUT,
    progress_callback: PortAnalysisProgressCallback | None = None,
    min_split_minutes: int = DEFAULT_PORT_ANALYSIS_MIN_RETRY_SPLIT_MINUTES,
) -> dict[str, Any]:
    """Build the exact port-analysis result for one policy."""
    base_filter = _build_policy_filter(policy_id, action)
    accumulator = await _run_cached_port_analysis_exact(
        policy_id=policy_id,
        adom=adom,
        device_filter=device_filter,
        time_range=full_time_range,
        action=action,
        filter_str=base_filter,
        timeout=fetch_timeout,
        slice_minutes=slice_minutes,
        progress_callback=progress_callback,
        min_split_minutes=min_split_minutes,
    )
    if accumulator.total_hits == 0:
        return _build_empty_port_analysis_result(policy_id)

    return {"policy_id": policy_id, **accumulator.build_result()}


async def _build_policy_protocol_summary_result(
    *,
    policy_id: int,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: str,
    full_time_range: dict[str, str],
    action: str | None,
    slice_day_candidates: list[int],
) -> dict[str, Any]:
    """Build the lightweight protocol summary for one policy."""
    base_filter = _build_policy_filter(policy_id, action)
    total_hits, sampled_protocols = await asyncio.gather(
        _run_log_count_exact(
            adom=adom,
            device_filter=device_filter,
            time_range=full_time_range,
            filter_str=base_filter,
            timeout=DEFAULT_POLICY_PROFILE_TIMEOUT,
            slice_day_candidates=slice_day_candidates,
        ),
        _discover_protocol_candidates(
            adom=adom,
            device_filter=device_filter,
            policy_filter=base_filter,
            time_range=time_range,
            sample_limit=DEFAULT_POLICY_SAMPLE_LIMIT,
            timeout=min(DEFAULT_POLICY_PROFILE_TIMEOUT, DEFAULT_SEARCH_TIMEOUT),
        ),
    )
    if total_hits == 0:
        return {"policy_id": policy_id, "total_hits": 0, "protocols": []}

    exact_protocol_hits, residual_protocol_hits = await _collect_protocol_buckets(
        adom=adom,
        device_filter=device_filter,
        time_range=full_time_range,
        base_filter=base_filter,
        base_protocols=SUMMARY_BASE_PROTOCOLS,
        total_hits=total_hits,
        timeout=DEFAULT_POLICY_PROFILE_TIMEOUT,
        sampled_protocols=sampled_protocols,
        slice_day_candidates=slice_day_candidates,
    )

    protocol_summary: list[ProtocolHit] = [
        {
            "protocol": _format_protocol_summary_name(protocol),
            "hits": hits,
        }
        for protocol, hits in exact_protocol_hits.items()
        if hits > 0
    ]
    if residual_protocol_hits > 0:
        protocol_summary.append({"protocol": "other", "hits": residual_protocol_hits})

    protocol_summary.sort(
        key=lambda item: (-int(item["hits"]), str(item["protocol"]))
    )

    return {
        "policy_id": policy_id,
        "total_hits": total_hits,
        "protocols": protocol_summary,
    }


async def _gather_policy_results(
    policy_ids: list[int],
    builder: Callable[[int], Awaitable[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Run per-policy builders with bounded concurrency."""

    async def run_policy(policy_id: int) -> dict[str, Any]:
        async with _POLICY_QUERY_SEMAPHORE:
            return await builder(policy_id)

    results = await asyncio.gather(
        *(run_policy(policy_id) for policy_id in policy_ids),
        return_exceptions=True,
    )

    per_policy = []
    for policy_id, result in zip(policy_ids, results, strict=True):
        if isinstance(result, Exception):
            per_policy.append({"policy_id": policy_id, "error": str(result)})
        else:
            per_policy.append(cast(dict[str, Any], result))

    return per_policy


def _build_port_analysis_job_state(
    *,
    job_id: str,
    adom: str,
    device: str | None,
    device_filter: list[dict[str, str]],
    policy_ids: list[int],
    time_range: str,
    full_time_range: dict[str, str],
    action: str | None,
    estimate: PortAnalysisEstimate,
) -> dict[str, Any]:
    """Build the initial persisted state for one background exact-analysis job."""
    now = _utc_timestamp()
    return {
        "version": PORT_ANALYSIS_JOB_SCHEMA_VERSION,
        "job_id": job_id,
        "status": "queued",
        "created_at": now,
        "updated_at": now,
        "request": {
            "adom": adom,
            "device": device,
            "device_filter": device_filter,
            "policy_ids": policy_ids,
            "time_range": time_range,
            "full_time_range": full_time_range,
            "action": action,
        },
        "estimate": _serialize_port_analysis_estimate(estimate),
        "progress": {
            "total_policies": len(policy_ids),
            "completed_policies": 0,
            "current_policy_id": None,
            "total_slices": 0,
            "completed_slices": 0,
            "cached_slices": 0,
            "computed_slices": 0,
            "split_slices": 0,
        },
        "result": None,
        "error": None,
    }


def _mark_port_analysis_job_interrupted(
    job_state: dict[str, Any],
    *,
    error: str | None = None,
) -> dict[str, Any]:
    """Mark a previously running job as interrupted in persisted state."""
    if job_state.get("status") in {"completed", "failed", "interrupted"}:
        return job_state
    job_state["status"] = "interrupted"
    job_state["updated_at"] = _utc_timestamp()
    if error:
        job_state["error"] = error
    elif not job_state.get("error"):
        job_state["error"] = "Background exact-analysis job is no longer active."
    return job_state


def mark_stale_port_analysis_jobs_interrupted(reason: str) -> int:
    """Mark persisted queued/running jobs as interrupted after a process restart."""
    jobs_dir = _get_port_analysis_jobs_dir()
    if not jobs_dir.exists():
        return 0

    interrupted = 0
    for job_path in jobs_dir.glob("*.json"):
        payload = _read_json_file(job_path)
        if not payload or payload.get("version") != PORT_ANALYSIS_JOB_SCHEMA_VERSION:
            continue
        if payload.get("status") not in {"queued", "running"}:
            continue
        _mark_port_analysis_job_interrupted(payload, error=reason)
        _write_json_atomic(job_path, payload)
        interrupted += 1
    return interrupted


async def shutdown_port_analysis_jobs(reason: str) -> int:
    """Cancel in-process background jobs and persist them as interrupted."""
    active_tasks = list(_PORT_ANALYSIS_JOB_TASKS.items())
    for job_id, task in active_tasks:
        job_state = _load_port_analysis_job_state(job_id)
        if job_state is not None:
            _mark_port_analysis_job_interrupted(job_state, error=reason)
            _store_port_analysis_job_state(job_state)
        task.cancel()

    if active_tasks:
        await asyncio.gather(
            *(task for _job_id, task in active_tasks),
            return_exceptions=True,
        )
    _PORT_ANALYSIS_JOB_TASKS.clear()
    return len(active_tasks)


async def _run_port_analysis_job(job_id: str) -> None:
    """Run one background exact port-analysis job to completion."""
    async with _PORT_ANALYSIS_JOB_SEMAPHORE:
        job_state = _load_port_analysis_job_state(job_id)
        if job_state is None:
            _PORT_ANALYSIS_JOB_TASKS.pop(job_id, None)
            return

        request = cast(dict[str, Any], job_state["request"])
        policy_ids = [int(policy_id) for policy_id in list(request["policy_ids"])]
        adom = str(request["adom"])
        device_filter = cast(list[dict[str, str]], request["device_filter"])
        full_time_range = cast(dict[str, str], request["full_time_range"])
        action = cast(str | None, request.get("action"))
        estimate = _deserialize_port_analysis_estimate(
            cast(dict[str, Any] | None, job_state.get("estimate"))
        )
        progress = cast(dict[str, Any], job_state["progress"])

        job_state["status"] = "running"
        job_state["updated_at"] = _utc_timestamp()
        _store_port_analysis_job_state(job_state)

        results: list[dict[str, Any]] = []
        started = time.monotonic()

        async def progress_callback(event: str, payload: dict[str, Any]) -> None:
            if event == "slices_planned":
                progress["total_slices"] = int(progress["total_slices"]) + int(payload.get("count", 0))
            elif event == "slice_split":
                progress["split_slices"] = int(progress["split_slices"]) + 1
                progress["total_slices"] = int(progress["total_slices"]) + 1
            elif event in {"slice_cached", "slice_computed"}:
                if int(progress["completed_slices"]) >= int(progress["total_slices"]):
                    progress["total_slices"] = int(progress["total_slices"]) + 1
                progress["completed_slices"] = int(progress["completed_slices"]) + 1
                if event == "slice_cached":
                    progress["cached_slices"] = int(progress["cached_slices"]) + 1
                else:
                    progress["computed_slices"] = int(progress["computed_slices"]) + 1
            job_state["updated_at"] = _utc_timestamp()
            _store_port_analysis_job_state(job_state)

        try:
            for policy_id in policy_ids:
                progress["current_policy_id"] = policy_id
                job_state["updated_at"] = _utc_timestamp()
                _store_port_analysis_job_state(job_state)
                try:
                    slice_minutes = _plan_port_analysis_slice_minutes(
                        full_time_range=full_time_range,
                        estimated_hits=estimate.hits_by_policy.get(policy_id),
                    )
                    result = await _build_policy_port_analysis_result(
                        policy_id=policy_id,
                        adom=adom,
                        device_filter=device_filter,
                        full_time_range=full_time_range,
                        action=action,
                        slice_minutes=slice_minutes,
                        fetch_timeout=DEFAULT_PORT_ANALYSIS_BACKGROUND_FETCH_TIMEOUT,
                        progress_callback=progress_callback,
                        min_split_minutes=DEFAULT_PORT_ANALYSIS_BACKGROUND_MIN_SPLIT_MINUTES,
                    )
                except Exception as exc:
                    result = {"policy_id": policy_id, "error": str(exc)}
                results.append(result)
                progress["completed_policies"] = int(progress["completed_policies"]) + 1
                progress["current_policy_id"] = None
                job_state["updated_at"] = _utc_timestamp()
                _store_port_analysis_job_state(job_state)

            job_state["status"] = "completed"
            job_state["result"] = {
                "status": "success",
                "results": results,
                "query_time_seconds": round(time.monotonic() - started, 2),
            }
            job_state["error"] = None
        except Exception as exc:
            job_state["status"] = "failed"
            job_state["error"] = str(exc)
        finally:
            progress["current_policy_id"] = None
            job_state["updated_at"] = _utc_timestamp()
            _store_port_analysis_job_state(job_state)
            _PORT_ANALYSIS_JOB_TASKS.pop(job_id, None)


def _aggregate_traffic_profile(logs: list[dict[str, Any]], top_n: int) -> dict[str, Any]:
    """Aggregate fetched log rows into a traffic profile."""
    port_counter: Counter[str] = Counter()
    service_counter: Counter[str] = Counter()
    app_counter: Counter[str] = Counter()

    for log in logs:
        dstport = log.get("dstport")
        proto = log.get("proto", "")
        if dstport is not None:
            port_counter[f"{proto}/{dstport}"] += 1

        service = log.get("service")
        if service:
            service_counter[str(service)] += 1

        app = log.get("app") or log.get("appcat")
        if app:
            app_counter[str(app)] += 1

    total = len(logs)
    top_ports = port_counter.most_common(top_n)
    top_services = service_counter.most_common(top_n)
    top_apps = app_counter.most_common(top_n)

    top_port_hits = sum(c for _, c in top_ports)
    top_service_hits = sum(c for _, c in top_services)
    top_app_hits = sum(c for _, c in top_apps)

    return {
        "total_hits": total,
        "top_ports": [{"port": p, "hits": c} for p, c in top_ports],
        "top_ports_residual": total - top_port_hits,
        "top_services": [{"service": s, "hits": c} for s, c in top_services],
        "top_services_residual": total - top_service_hits,
        "top_applications": [{"application": a, "hits": c} for a, c in top_apps],
        "top_applications_residual": total - top_app_hits,
    }


def _aggregate_port_analysis(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate a complete fetched log set into an exact port/protocol summary."""
    accumulator = PortAnalysisAccumulator()
    accumulator.consume_rows(logs)
    return accumulator.build_result()


def _aggregate_protocol_summary(logs: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate fetched log rows into a lightweight protocol summary."""
    protocol_counter: Counter[str] = Counter()
    total = len(logs)

    for log in logs:
        proto_num = str(log.get("proto", "unknown"))
        protocol_counter[_format_protocol_name(proto_num)] += 1

    return {
        "total_hits": total,
        "protocols": [{"protocol": p, "hits": c} for p, c in protocol_counter.most_common()],
    }


@mcp.tool()
async def get_policy_traffic_profile(
    adom: str | None = None,
    device: str | None = None,
    policy_ids: list[int] | None = None,
    time_range: str = "24-hour",
    action: str | None = None,
    top_n: int = DEFAULT_TOP_N,
) -> dict[str, Any]:
    """Get sampled traffic summaries for one or more firewall policies.

    The results are built from multi-slice discovery plus exact recounts of the
    strongest candidates, so this stays fast while still grounding the reported
    hits in full-window counts.
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        if policy_ids is None:
            return {"status": "error", "message": "policy_ids is required"}
        policy_ids = validate_policy_ids(policy_ids)
        action = validate_action(action)
        if top_n < 1:
            top_n = DEFAULT_TOP_N

        device_filter = _build_device_filter(device)
        full_time_range = _parse_time_range(time_range)
        slice_day_candidates = _build_exact_slice_day_candidates(DEFAULT_EXACT_SLICE_DAYS)
        discovery_slice_days = _plan_batch_slice_days(
            time_range=time_range,
            slice_days=1,
            policy_count=len(policy_ids),
            fields=("port_pair", "service", "app"),
        )

        start = time.monotonic()
        results = await _gather_policy_results(
            policy_ids,
            lambda policy_id: _build_policy_traffic_profile_result(
                policy_id=policy_id,
                adom=adom,
                device_filter=device_filter,
                time_range=time_range,
                full_time_range=full_time_range,
                action=action,
                top_n=top_n,
                slice_day_candidates=slice_day_candidates,
                discovery_slice_days=discovery_slice_days,
            ),
        )

        return {
            "status": "success",
            "results": results,
            "query_time_seconds": round(time.monotonic() - start, 2),
        }
    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except RuntimeError as e:
        return {"status": "error", "message": str(e)}
    except (OSError, TimeoutError, FazConnectionError, FazTimeoutError, APIError) as e:
        logger.error(f"Network error in get_policy_traffic_profile: {e}")
        return {"status": "error", "message": f"Network error: {e}"}


@mcp.tool()
async def get_policy_port_analysis(
    adom: str | None = None,
    device: str | None = None,
    policy_ids: list[int] | None = None,
    time_range: str = "24-hour",
    action: str | None = None,
) -> dict[str, Any]:
    """Get exact port/protocol analysis for one or more firewall policies.

    This uses a full exact traffic-log fetch for each policy/time window and
    aggregates pages locally, so the returned ports, protocols, and ICMP
    breakdown are 1:1 with the fetched logs whenever the query completes
    successfully. Large requests fail closed before execution when the server
    estimates they are too expensive for one synchronous call.
    """
    try:
        adom = validate_adom(adom or get_default_adom())
        if policy_ids is None:
            return {"status": "error", "message": "policy_ids is required"}
        policy_ids = validate_policy_ids(policy_ids)
        action = validate_action(action)

        device_filter = _build_device_filter(device)
        full_time_range = _parse_time_range(time_range)
        fully_cached = all(
            _has_cached_port_analysis_accumulator(
                adom=adom,
                device_filter=device_filter,
                policy_id=policy_id,
                action=action,
                time_range=full_time_range,
            )
            for policy_id in policy_ids
        )
        run_plan = PortAnalysisRunPlan(estimate=PortAnalysisEstimate(complete=True))
        if fully_cached:
            run_plan.policy_slice_minutes = {
                policy_id: _plan_port_analysis_slice_minutes(
                    full_time_range=full_time_range,
                    estimated_hits=None,
                )
                for policy_id in policy_ids
            }
            logger.info("Port-analysis request for policies %s served from exact cache", policy_ids)
        else:
            estimate = PortAnalysisEstimate()
            if not _should_skip_port_analysis_estimate(
                policy_ids=policy_ids,
                full_time_range=full_time_range,
            ):
                estimate = await _estimate_port_analysis_hits(
                    adom=adom,
                    device_filter=device_filter,
                    full_time_range=full_time_range,
                    policy_ids=policy_ids,
                    action=action,
                )
            run_plan = _plan_port_analysis_run(
                policy_ids=policy_ids,
                full_time_range=full_time_range,
                estimate=estimate,
            )
            logger.info(
                "Port-analysis plan for policies %s: execute=%s slices=%d pages=%d est_seconds=%.2f reason=%s",
                policy_ids,
                run_plan.should_execute,
                run_plan.estimated_total_slices,
                run_plan.estimated_total_pages,
                run_plan.estimated_wall_seconds,
                run_plan.reason,
            )
            guard_error = _port_analysis_guard_error(
                policy_ids=policy_ids,
                full_time_range=full_time_range,
                plan=run_plan,
            )
            if guard_error:
                return {"status": "error", "message": guard_error}

        start = time.monotonic()
        results = await _gather_policy_results(
            policy_ids,
            lambda policy_id: _build_policy_port_analysis_result(
                policy_id=policy_id,
                adom=adom,
                device_filter=device_filter,
                full_time_range=full_time_range,
                action=action,
                slice_minutes=run_plan.policy_slice_minutes[policy_id],
            ),
        )

        return {
            "status": "success",
            "results": results,
            "query_time_seconds": round(time.monotonic() - start, 2),
        }
    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except RuntimeError as e:
        return {"status": "error", "message": str(e)}
    except (OSError, TimeoutError, FazConnectionError, FazTimeoutError, APIError) as e:
        logger.error(f"Network error in get_policy_port_analysis: {e}")
        return {"status": "error", "message": f"Network error: {e}"}


@mcp.tool()
async def get_policy_protocol_summary(
    adom: str | None = None,
    device: str | None = None,
    policy_ids: list[int] | None = None,
    time_range: str = "24-hour",
    action: str | None = None,
) -> dict[str, Any]:
    """Get lightweight protocol summaries with exact bucket counts plus residual `other`."""
    try:
        adom = validate_adom(adom or get_default_adom())
        if policy_ids is None:
            return {"status": "error", "message": "policy_ids is required"}
        policy_ids = validate_policy_ids(policy_ids)
        action = validate_action(action)

        device_filter = _build_device_filter(device)
        full_time_range = _parse_time_range(time_range)
        slice_day_candidates = _build_exact_slice_day_candidates(DEFAULT_EXACT_SLICE_DAYS)

        start = time.monotonic()
        results = await _gather_policy_results(
            policy_ids,
            lambda policy_id: _build_policy_protocol_summary_result(
                policy_id=policy_id,
                adom=adom,
                device_filter=device_filter,
                time_range=time_range,
                full_time_range=full_time_range,
                action=action,
                slice_day_candidates=slice_day_candidates,
            ),
        )

        return {
            "status": "success",
            "results": results,
            "query_time_seconds": round(time.monotonic() - start, 2),
        }
    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except RuntimeError as e:
        return {"status": "error", "message": str(e)}
    except (OSError, TimeoutError, FazConnectionError, FazTimeoutError, APIError) as e:
        logger.error(f"Network error in get_policy_protocol_summary: {e}")
        return {"status": "error", "message": f"Network error: {e}"}


@mcp.tool()
async def start_policy_port_analysis_job(
    adom: str | None = None,
    device: str | None = None,
    policy_ids: list[int] | None = None,
    time_range: str = "24-hour",
    action: str | None = None,
) -> dict[str, Any]:
    """Start a background exact port-analysis job for long-running policy windows."""
    try:
        adom = validate_adom(adom or get_default_adom())
        if policy_ids is None:
            return {"status": "error", "message": "policy_ids is required"}
        policy_ids = validate_policy_ids(policy_ids)
        action = validate_action(action)

        device_filter = _build_device_filter(device)
        full_time_range = _parse_time_range(time_range)
        estimate = PortAnalysisEstimate()
        if not _should_skip_port_analysis_estimate(
            policy_ids=policy_ids,
            full_time_range=full_time_range,
        ):
            estimate = await _estimate_port_analysis_hits(
                adom=adom,
                device_filter=device_filter,
                full_time_range=full_time_range,
                policy_ids=policy_ids,
                action=action,
            )
        job_id = uuid.uuid4().hex
        job_state = _build_port_analysis_job_state(
            job_id=job_id,
            adom=adom,
            device=device,
            device_filter=device_filter,
            policy_ids=policy_ids,
            time_range=time_range,
            full_time_range=full_time_range,
            action=action,
            estimate=estimate,
        )
        _store_port_analysis_job_state(job_state)

        task = asyncio.create_task(_run_port_analysis_job(job_id))
        _PORT_ANALYSIS_JOB_TASKS[job_id] = task

        return {
            "status": "success",
            "job_id": job_id,
            "job_status": job_state["status"],
            "request": job_state["request"],
            "message": "Background exact port-analysis job started.",
        }
    except ValidationError as e:
        return {"status": "error", "message": f"Validation error: {e}"}
    except RuntimeError as e:
        return {"status": "error", "message": str(e)}
    except (OSError, TimeoutError, FazConnectionError, FazTimeoutError, APIError) as e:
        logger.error(f"Network error in start_policy_port_analysis_job: {e}")
        return {"status": "error", "message": f"Network error: {e}"}


@mcp.tool()
async def get_policy_port_analysis_job(job_id: str) -> dict[str, Any]:
    """Get the current status or final result for a background exact-analysis job."""
    job_id = job_id.strip()
    if not job_id:
        return {"status": "error", "message": "job_id is required"}

    job_state = _load_port_analysis_job_state(job_id)
    if job_state is None:
        return {"status": "error", "message": f"Unknown job_id: {job_id}"}

    task = _PORT_ANALYSIS_JOB_TASKS.get(job_id)
    if job_state.get("status") in {"queued", "running"} and (task is None or task.done()):
        error: str | None = None
        if task is not None:
            try:
                exc = task.exception()
            except asyncio.InvalidStateError:
                exc = None
            if exc is not None:
                error = str(exc)
        job_state = _mark_port_analysis_job_interrupted(job_state, error=error)
        _store_port_analysis_job_state(job_state)
        _PORT_ANALYSIS_JOB_TASKS.pop(job_id, None)

    return {"status": "success", "job": job_state}
