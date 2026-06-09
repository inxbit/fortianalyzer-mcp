# FortiAnalyzer MCP — Log Search

This context covers how the MCP runs LogView searches against a FortiAnalyzer appliance
(`logsearch` start / count / fetch / cancel) and surfaces rows to MCP callers.

## Language

**Search readiness** (a.k.a. completion):
The point at which a FAZ log search has finished scanning and its results are safe to fetch.
Signaled by the `count` endpoint reporting `progress-percent >= 100`, or `scanned-logs >= total-logs`
when `total-logs > 0`. Reaching readiness is a precondition for fetching.
_Avoid_: "done", "100%" (ambiguous with premature-100).

**matched-logs**:
The count of rows matching the filter found *so far* during a scan. Proves matches exist; does **not**
prove the scan is finished, so it is never a readiness signal.
_Avoid_: using as "total" or "complete".

**total-count**:
The count of matching rows for one completed search, read from that `fetch` response — authoritative
for that search/page. Cross-page total stability is not guaranteed (each page is an independent
search).
_Avoid_: `total-logs` (a scan-progress figure, not the match total).

**Appliance TID**:
The single-use task id returned by `logsearch_start`. The first `fetch` reaps it (`count` does not);
once reaped it is a dead value the appliance no longer recognizes as a live task.
_Avoid_: "task id".

**Pagination handle**:
The `tid` the MCP returns to callers for paging. It is the *reaped* Appliance TID value reused as an
opaque key in a local registry — never re-sent to the appliance as a live task; paging reconstructs a
fresh search at the new offset from the registered params.
_Avoid_: implying it is a still-live appliance task.

**Premature-100**:
FAZ 7.6.7 behavior where a fetch reports `percentage >= 100` with empty `data` while more rows exist
(`total-count > offset`). Triggers a bounded re-issue.
_Avoid_: "empty result" (a real zero-result is distinct).

**Slot exhaustion**:
The failure mode this work fixes: a search loop re-issues `logsearch_start` faster than searches
finish, draining the appliance's search-slot pool → `No available slot` / `search_timeout` / zero rows.
_Avoid_: "rate limit" (unrelated; that was a red herring).

**Compat fallback**:
On older builds whose `count` endpoint is absent, a single direct fetch substitutes for the poll loop,
detected only by an unsupported-endpoint error and cached per client.
_Avoid_: triggering it on invalid-tid / timeout / generic errors.
