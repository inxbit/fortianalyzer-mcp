# Poll `logsearch_count` before fetching log search results

**Status:** accepted

## Context

FAZ log search is asynchronous: `logsearch_start` returns a single-use appliance TID, the scan
runs, and the first `logsearch_fetch` both returns the page and reaps the TID. Earlier code (and an
inline comment) assumed "the fetch blocks server-side until the search completes," so it fetched
immediately after start. On live 7.6.7 the fetch instead returns *incomplete* and reaps the TID, so
the page-runner re-issued a fresh search ~once/second; ~60 starts/60s drained the appliance
search-slot pool (Slot exhaustion → `No available slot` / `search_timeout` / zero rows). The mocked
test suite never caught it because fakes returned `percentage:100` instantly.

## Decision

Make **poll-before-fetch** the hard contract for every appliance log search: `logsearch_start` →
poll `logsearch_count` (does not reap) until Search readiness → `logsearch_fetch` exactly once. A
single shared page-runner enforces it for `query_logs`, `fetch_more_logs`, the bounded policy
slices, and the PCAP searches.

Two structural guards make the anti-exhaustion guarantee explicit rather than emergent:
- a shared **recovery budget** (`MAX_SEARCH_REISSUES = 3`) caps re-issues across all causes
  (invalid-tid during count, invalid-tid during fetch, premature-100), so a reaping appliance can
  never spin starts; and
- a module-level **concurrency semaphore** (`LOGSEARCH_CONCURRENCY_LIMIT = 4`) around the whole
  start→poll→fetch lifecycle, because each search now legitimately *holds* a slot until readiness —
  bounding total in-flight appliance searches across every call site in the process.

## Consequences

- Adds a poll phase (immediate first check, 0.25→1.0s backoff) — a few hundred ms for typical
  searches, far less than the old failure mode.
- Searches now hold a slot until readiness; the global semaphore is what keeps wide policy fan-outs
  and parallel tool calls from re-creating exhaustion. For policy paths the global `LOGSEARCH`
  semaphore nests *inside* the pre-existing policy `_QUERY_SEMAPHORE(5)` (policy acquired first, then
  global); the global guard is the binding appliance-slot constraint and the acquire order is
  globally consistent, so no deadlock.
- A clean `search_timeout` on genuinely large windows is acceptable; it is a failure only if it
  leaks a raw `Invalid tid`, loops starts, leaves running tasks, or ignores the supplied timeout.
