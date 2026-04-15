# Cross-MCP Policy Hardening Workflow

This document describes a practical workflow that combines:

- **FortiAnalyzer MCP** for observed traffic analysis
- **FortiManager MCP** for reviewing and updating policy configuration

The goal is to tighten firewall policy safely by basing changes on real traffic rather than assumptions.

## Overview

Policy hardening usually answers two separate questions:

1. What traffic is actually using this policy?
2. How should the policy be changed to allow only that traffic?

FortiAnalyzer MCP answers the first question. It is read-only and reports observed traffic patterns over a chosen time window.

FortiManager MCP answers the second question. It is where policy objects, services, and rule definitions are reviewed and changed.

Used together, the two MCPs support a closed-loop workflow:

1. Identify candidate policies
2. Analyze observed usage in FortiAnalyzer
3. Compare observed usage to configured services in FortiManager
4. Decide whether a tighter service set is safe
5. Apply and validate the change in FortiManager

## End-to-End Workflow

### 1. Choose a policy and a time window

Start with a policy that looks broader than necessary, such as one allowing `ALL`, very large service groups, or legacy temporary exceptions.

Pick a time window that is long enough to capture real usage:

- `24-hour` for very active policies
- `7-day` for normal validation
- `30-day` or longer for low-frequency or business-cycle traffic

### 2. Profile the policy in FortiAnalyzer MCP

Use the traffic analysis tools to understand what the policy is carrying.

Recommended sequence:

1. `get_policy_traffic_profile`
2. `get_policy_port_analysis`
3. `get_policy_protocol_summary`

What each tool contributes:

- `get_policy_traffic_profile` highlights the most important ports, services, and applications using sampled discovery plus exact recounts of the strongest candidates.
- `get_policy_port_analysis` gives the strongest evidence for change planning because it reports exact protocol and numeric-port usage and tells you whether the numeric-port coverage is fully exact via `is_exact`.
- `get_policy_protocol_summary` gives a compact exact protocol mix for fast review across multiple policies.

### 3. Interpret the analysis before proposing change

Look for patterns such as:

- One or two numeric ports dominating a policy that currently allows `ALL`
- Only TCP/443 and TCP/8443 appearing on a policy with a large service group
- ICMP-only behavior on troubleshooting or monitoring paths
- Portless protocols such as GRE, ESP, AH, or OSPF that should not be modeled as TCP/UDP service objects

If `get_policy_port_analysis` returns `is_exact = false`, treat the result as incomplete for numeric ports. In that case:

- keep the current policy broader for now, or
- extend the time window, or
- investigate the residual uncovered numeric-port hits before tightening

### 4. Review the configured policy in FortiManager MCP

Once observed traffic is understood, switch to FortiManager MCP and inspect the configured rule.

Typical review questions:

- Which services or service groups are attached to the policy today?
- Does the configured service set already match observed traffic?
- Are there legacy objects that can be removed?
- Are there protocol-specific objects needed for non-port-bearing traffic?

This is the configuration side of the workflow. FortiAnalyzer shows what happened. FortiManager shows what is allowed.

### 5. Compare observed usage to configured services

Build the proposed change set by comparing:

- Observed numeric ports and protocols from FortiAnalyzer
- Configured services and service groups from FortiManager

Good candidates for hardening:

- Configured `ALL` but observed usage is a small stable set
- Large service group but only a subset is used
- Temporary exceptions that no longer appear in traffic

Bad candidates for immediate hardening:

- Policies with low-volume, sporadic traffic on long business cycles
- Policies with `is_exact = false` and unresolved uncovered numeric-port hits
- Policies carrying dynamic or opaque protocols not well represented by simple service objects

### 6. Apply the policy change in FortiManager MCP

After review, use FortiManager MCP to:

- replace `ALL` with a tighter service set
- remove unused services from groups
- preserve required protocol-specific allowances
- document the change reason using the FortiAnalyzer observations

### 7. Validate after the change

After deployment, re-run the FortiAnalyzer traffic tools for the same policy and an appropriate post-change window to confirm:

- expected traffic still passes
- no missing required services appear
- the tightened policy still matches real behavior

## Example Agent Prompts

### FortiAnalyzer-first prompts

```text
Analyze policy 38 over the last 30 days. Show sampled traffic profile, exact port analysis, and exact protocol summary.
```

```text
For policies 12, 18, and 46, identify which ones are good candidates for tightening based on exact observed traffic.
```

```text
Explain whether policy 46 is safe to tighten. If get_policy_port_analysis is not exact, tell me what remains unresolved.
```

### Cross-MCP prompts

```text
Use FortiAnalyzer MCP to analyze policy 38 over the last 30 days, then use FortiManager MCP to compare the configured services to the observed traffic and propose a tighter service set.
```

```text
Find policies that still allow ALL, rank them by hardening potential, and for the top candidate compare FortiAnalyzer observations against the FortiManager policy definition.
```

```text
Review policy 46 end to end: observed traffic in FortiAnalyzer, configured services in FortiManager, and a recommended change plan with caveats.
```

## Tool Reference

| MCP | Tool | Purpose | Returns |
|-----|------|---------|---------|
| FortiAnalyzer | `get_policy_traffic_profile` | Read-only traffic profiling for top ports, services, and applications | Per-policy sampled discovery with exact recounts and residual counters |
| FortiAnalyzer | `get_policy_port_analysis` | Read-only exact port/protocol analysis | Per-policy ports, protocols, `portless_protocols`, ICMP details, `uncovered_port_hits`, and `is_exact` |
| FortiAnalyzer | `get_policy_protocol_summary` | Read-only exact protocol summary | Per-policy protocol distribution |
| FortiManager | `get_policy_services` | Review configured services on a policy | Current service and service-group configuration for comparison |

## Caveats

### Sampled vs exact results

Not every traffic-analysis output has the same strength:

- `get_policy_traffic_profile` is optimized for fast profiling. It uses sampled discovery and exact recounts for the strongest discovered values.
- `get_policy_port_analysis` is the strongest source for numeric-port tightening because it reports whether numeric-port coverage is fully exact.
- `get_policy_protocol_summary` is exact at the protocol level, but it is not a substitute for full port analysis.

### Time windows matter

A clean result over `24-hour` may still miss:

- weekend-only jobs
- monthly or quarterly processes
- backup or maintenance traffic
- rare error-handling or failover paths

Use a time window that matches the policy's real operational cycle.

### `is_exact` only answers one question

`is_exact` tells you whether the numeric-port coverage in the selected window is fully represented by the returned `ports` list.

It does **not** mean:

- the policy is safe to harden without business review
- the chosen time window is long enough
- future traffic will never change

### Portless protocols need separate treatment

Protocols such as ICMP, GRE, ESP, AH, OSPF, and similar traffic are not modeled the same way as TCP/UDP destination ports. Review them explicitly before converting a broad rule into a port-only service list.

## Recommended Decision Rule

Use this workflow when all of the following are true:

- observed traffic is stable over a representative time window
- `get_policy_port_analysis` has no unresolved numeric-port gap for the decision
- the FortiManager configuration clearly allows more than is actually used
- the policy owner agrees that the observed set reflects intended behavior

If any of these conditions fail, treat the result as advisory rather than actionable.
