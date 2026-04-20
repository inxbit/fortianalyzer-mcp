"""Policy traffic analysis tools for FortiAnalyzer.

Provides tools for analyzing observed traffic patterns per firewall policy:
- sampled traffic profiling (top ports, services, applications)
- exact port and protocol analysis with truthful exactness semantics
- lightweight protocol distribution summaries

These tools support policy-review and policy-tightening preparation workflows.
"""

import asyncio
import logging
import math
import time
from collections import Counter
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
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

# Concurrency limit for per-policy work.
_POLICY_QUERY_SEMAPHORE = asyncio.Semaphore(5)

# Default and max search parameters.
DEFAULT_SEARCH_TIMEOUT = 120
POLL_INTERVAL = 0.25
MAX_POLICY_IDS = 25
DEFAULT_TOP_N = 10
DEFAULT_POLICY_PROFILE_TIMEOUT = 20
DEFAULT_PORT_ANALYSIS_FETCH_TIMEOUT = 120
DEFAULT_EXACT_FETCH_PAGE_SIZE = 500
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


async def _run_log_fetch_all(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter_str: str | None,
    timeout: int,
    page_size: int = DEFAULT_EXACT_FETCH_PAGE_SIZE,
    retries: int = 2,
) -> list[dict[str, Any]]:
    """Run one full log search and fetch every matching row exactly."""
    last_error: Exception | None = None
    page_size = max(1, min(page_size, DEFAULT_EXACT_FETCH_PAGE_SIZE))

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

                        rows.extend(page_rows)
                        offset += len(page_rows)
                        if expected_total is None and len(page_rows) < page_size:
                            break

                    if expected_total is not None and len(rows) < expected_total:
                        raise RuntimeError(
                            f"Incomplete exact fetch for filter {filter_str}: "
                            f"expected {expected_total} rows, got {len(rows)}"
                        )
                    return rows[:expected_total] if expected_total is not None else rows

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

    raise RuntimeError(f"Exact fetch failed for filter {filter_str}: {last_error}")


async def _run_log_fetch_resilient(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter_str: str | None,
    timeout: int,
    min_split_hours: int = 1,
) -> list[dict[str, Any]]:
    """Run a full exact fetch, splitting the time range when one query is too slow."""
    try:
        return await _run_log_fetch_all(
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
        left_rows = await _run_log_fetch_resilient(
            adom=adom,
            device_filter=device_filter,
            time_range=left_range,
            filter_str=filter_str,
            timeout=timeout,
            min_split_hours=min_split_hours,
        )
        right_rows = await _run_log_fetch_resilient(
            adom=adom,
            device_filter=device_filter,
            time_range=right_range,
            filter_str=filter_str,
            timeout=timeout,
            min_split_hours=min_split_hours,
        )
        return left_rows + right_rows


async def _run_log_fetch_exact(
    *,
    adom: str,
    device_filter: list[dict[str, str]],
    time_range: dict[str, str],
    filter_str: str | None,
    timeout: int,
    slice_day_candidates: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Fetch every matching log row exactly, using fixed slices before recursive splits."""
    candidates = slice_day_candidates or [1]
    last_error: Exception | None = None

    for slice_days in candidates:
        try:
            rows: list[dict[str, Any]] = []
            for time_slice in _build_exact_time_slices(time_range, slice_days):
                rows.extend(
                    await _run_log_fetch_all(
                        adom=adom,
                        device_filter=device_filter,
                        time_range=time_slice,
                        filter_str=filter_str,
                        timeout=timeout,
                    )
                )
            return rows
        except RETRYABLE_QUERY_EXCEPTIONS as exc:
            last_error = exc

    if last_error is not None:
        return await _run_log_fetch_resilient(
            adom=adom,
            device_filter=device_filter,
            time_range=time_range,
            filter_str=filter_str,
            timeout=timeout,
        )

    raise RuntimeError(f"Exact fetch failed for filter {filter_str}")


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
                    for field in counters:
                        normalized = _normalize_sample_value(field, row.get(field), row)
                        if normalized:
                            counters[field][normalized] += 1

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
    slice_day_candidates: list[int],
) -> dict[str, Any]:
    """Build the exact port-analysis result for one policy."""
    base_filter = _build_policy_filter(policy_id, action)
    logs = await _run_log_fetch_exact(
        adom=adom,
        device_filter=device_filter,
        time_range=full_time_range,
        filter_str=base_filter,
        timeout=DEFAULT_PORT_ANALYSIS_FETCH_TIMEOUT,
        slice_day_candidates=slice_day_candidates,
    )
    if not logs:
        return _build_empty_port_analysis_result(policy_id)

    return {"policy_id": policy_id, **_aggregate_port_analysis(logs)}


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
    port_counter: Counter[str] = Counter()
    protocol_counter: Counter[str] = Counter()
    portless_protocols: set[str] = set()
    icmp_types: Counter[str] = Counter()
    total = len(logs)

    for log in logs:
        proto_str = str(log.get("proto", "unknown")).strip() or "unknown"
        protocol_counter[proto_str] += 1

        dstport = log.get("dstport")
        if dstport is not None and str(dstport).isdigit() and str(dstport) != "0":
            port_counter[f"{proto_str}/{dstport}"] += 1
        else:
            portless_protocols.add(proto_str)

        if proto_str == "1":
            service = str(log.get("service", ""))
            if service:
                icmp_types[_format_icmp_type_code(service)] += 1

    return {
        "total_hits": total,
        "is_exact": True,
        "ports": sorted(
            [{"port": p, "hits": c} for p, c in port_counter.items()],
            key=lambda item: (-int(item["hits"]), _port_pair_sort_key(str(item["port"]))),
        ),
        "protocols": sorted(
            [{"protocol": p, "hits": c} for p, c in protocol_counter.items()],
            key=lambda item: (-int(item["hits"]), _protocol_sort_key(str(item["protocol"]))),
        ),
        "portless_protocols": sorted(portless_protocols, key=_protocol_sort_key),
        "uncovered_port_hits": 0,
        "icmp": sorted(
            [{"type_code": key, "hits": hits} for key, hits in icmp_types.items()],
            key=lambda item: (-int(item["hits"]), str(item["type_code"])),
        ),
    }


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
    aggregates locally, so the returned ports, protocols, and ICMP breakdown
    are 1:1 with the fetched logs whenever the query completes successfully.
    """
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
            lambda policy_id: _build_policy_port_analysis_result(
                policy_id=policy_id,
                adom=adom,
                device_filter=device_filter,
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
