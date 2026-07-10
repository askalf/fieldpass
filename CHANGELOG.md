# Changelog

## 0.2.1

- **Renamed: `@askalf/picket` → `@askalf/fieldpass`** (npm-publishable name; `picket` is squatted unscoped and the registry create-policy blocks colliding scoped names). GitHub repo becomes `askalf/fieldpass` (old URLs redirect). Legacy `picket`/`picket-mcp` bin aliases retained; MCP tool names and `PICKET_*` env vars unchanged.

All notable changes to `@askalf/picket` are documented here.

## [Unreleased]

### Added

- **Streamable HTTP transport for the MCP server** — `picket-mcp --http`
  serves `picket_observe` / `picket_gate` / `picket_login` as a URL-type MCP
  server, so clients that can't spawn a stdio process (the Claude API MCP
  connector, Managed Agents, remote agent runtimes) can attach. Spec session
  management with every session sharing one governed browser (verdict cache
  and keeper leases persist, same as stdio); binds `127.0.0.1` by default with
  DNS-rebinding protection on loopback, optional constant-time bearer auth
  (`PICKET_MCP_TOKEN`), and an unauthenticated `GET /healthz` liveness probe.
  stdio stays the default transport.
- **Framework example series** — four runnable, offline, no-API-key examples
  of real agent-framework engines browsing behind the firewall via
  `picket-mcp`: LangGraph.js (`StateGraph`), OpenAI Agents SDK (scripted
  offline model through the genuine `Runner`), CrewAI (`Flow`), and Microsoft
  AutoGen (`AssistantAgent` + `McpWorkbench`). Each reads a booby-trapped
  invoice page, proves the injection is withheld while benign content
  survives, has every hijack action refused at the gate, and shows login
  failing closed with no vault — with captured evidence and pinned versions
  from real runs in each example's `evidence/`.

## [0.2.0] — 2026-07-01

The complete prototype→product roadmap since the initial release: LLM-judge
escalation, an MCP server, a persona context broker, a replay-verification
oracle, canon-pinnable browser skills, and a hardened firewall core.

### Added

- **LLM-judge escalation tier** — a configurable Claude backend reviews only
  the ambiguous residue the deterministic detector can't rule on, with
  confidence calibration and a message-id round-trip fix (#1), plus a
  content-keyed verdict cache (bounded LRU, fail-safe) to cut repeat LLM
  calls (#3). Escalate-only and inert on error.
- **MCP server** — `picket_observe` / `picket_gate` / `picket_login` exposed
  over stdio via the `picket-mcp` entrypoint, so any MCP client gets the
  governed browser (#4). Observe returns verdict and finding categories only —
  withheld excerpts never cross the wire.
- **ContextBroker** — a pool of isolated, keeper-backed persona contexts on one
  shared browser: login-once per persona, LRU eviction, and non-destructive
  teardown (disconnect, never close) (#5).
- **Replay-verification oracle** — a deterministic snapshot / diff /
  claim-verification gate that culls fabricated "the page shows X" claims
  without an LLM, and flags clean-golden → injection regressions (#6).
- **Canon browser skills** — record a governed session and emit it as a
  canon-pinnable, deterministically replayable skill manifest; secrets are
  redacted and the sha256 skill hash matches canon's pin (#7).
- npm publish workflow and `publishConfig.access: public` (#10).

### Fixed

- **Firewall + action-gate hardening** (#2): `observe()` now prefers the live
  CDP bridge over the static parser when both are available; cross-node
  split-trifecta detection catches legs scattered across sibling nodes; the
  gate default-denies unknown action types; credential typing is inferred from
  field shape even without the flag; the nav allowlist matches `hostname`
  (not host:port); and `data:` / `javascript:` / `blob:` URLs count as exfil
  sinks.
- **Live CDP capture parity** (#8): low-contrast hidden text uses the same
  color-distance threshold as the static backend, and `value` attributes are
  scanned — closing two evasions that only affected the live path.
- The oracle reuses the detector's canonical action lattice instead of a local
  copy (#9).

### Docs

- README repositioned: picket is a standalone Own Your Stack tool that
  composes with the warden · canon · keeper trilogy (#11).

## [0.1.0] — 2026-06-19

Initial public release: deterministic lethal-trifecta detector
(capture → detect → policy → safe view), action gate with warden forwarding,
keeper-backed login that keeps secrets out of agent context, static and live
CDP capture backends, `picket scan` CLI, and the naive-vs-governed demos.
