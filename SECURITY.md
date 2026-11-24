# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.3.x   | Yes       |
| < 0.3.0 | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in **Async-Shield** (for example: signature verification bypass, canonicalization ambiguity, lattice join flaw, capability-allowlist bypass, audience-binding bypass, or replay protection bypass):

1. **Do not** open a public GitHub issue with exploit details.
2. Report it privately using GitHub Security Advisories (`Security` -> `Advisories` -> `Report a vulnerability`) on the repository, or contact the maintainers directly.
3. Include a minimal reproduction script, affected version, and expected vs. actual behavior.

We aim to acknowledge reports within 48 hours and provide a coordinated remediation timeline.

## Security Model & Scope Reminders

Before reporting an issue, please review the **Threat Model & Explicit Limitations** section in [README.md](README.md). In particular, the following are intentional design boundaries rather than vulnerabilities:

- **Symmetric HMAC verifier limitation (Ed25519 planned):** Because `v0.3.x` uses symmetric HMAC-SHA256, any node holding a verification key (for example, the Executor holding `admin-v1` to verify `HIGH` admin envelopes) can technically also sign envelopes under that `kid`. This relies on the Executor being inside the TCB; moving to asymmetric signatures (**Ed25519**) so verifiers hold only public keys is planned.
- **At-most-once (not exactly-once) replay semantics:** `RedisReplayStore` consumes the nonce (`SET NX EX`) before executing the protected tool. If the tool crashes mid-execution, redelivery is blocked (fail-closed) rather than risking duplicate side effects; recovery requires checking side-effect state and issuing a fresh envelope with a new `nonce`.
- **Fail-closed on Redis unavailability:** If `RedisReplayStore` cannot reach Redis, `SinkGate` raises `ReplayStoreUnavailableError` and refuses to execute the tool.
- **Availability & ordering:** Any writer with Redis access can delete, delay, or reorder stream entries. Because `EnvelopeMetadata` (`hop_count`, `retry_count`, DLQ fields) is intentionally outside the signed core, a malicious Redis writer can tamper with `retry_count` to accelerate DLQ routing (DoS, not integrity or capability escalation).
- **Integrity-only (Biba), no confidentiality:** Async-Shield does not prevent data exfiltration through sinks that are explicitly authorized for `LOW`-integrity data.
- **No in-LLM taint tracking (coarse-grained Planner cap):** Async-Shield does not track information flow inside the LLM itself; the Planner worker is statically capped at `LOW` integrity via its role key, so all Planner outputs are treated conservatively as `LOW`.
- **No dynamic endorsement:** `LOW`-integrity inputs cannot be promoted to `HIGH` inside the pipeline without an out-of-band authoritative issuer holding a `HIGH`-scoped key.
- **Out-of-band shared state:** External scratchpads, caches, or databases written by an LLM worker and read later outside `ShieldBroker` do not carry `StreamEnvelope` labels.
- **Clock skew:** `expires_at` enforcement assumes reasonably synchronized NTP clocks across producers and executors (bounded by `clock_skew_seconds` on `SinkGate`).
