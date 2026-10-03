# Architecture and learning milestones

## 1 — Telemetry and normalization
The generator creates Windows-style authentication/process records and sensor-style DNS,
network, firewall and endpoint records. Separate parsers translate vendor keys into one
Pydantic Event. Timezones, IP addresses and port ranges are checked. Original fields are
retained under raw_event so an analyst can verify what normalization did.
The ingestion reader rejects malformed records with line numbers; exact duplicate IDs are
deduplicated and conflicting duplicates fail. File-level failure avoids silently missing evidence.

## 2 — Detection engineering
Small rule modules receive timestamp-ordered events. Authentication uses rolling source windows;
process detection uses command-line indicators; identity tracks previous login sites; network
checks a lab indicator and preceding privileged authentication. Labels are never detection inputs.
The authentication engine emits once per burst/window-start key. Long bursts can emit again as
the oldest event expires: production deployments should implement durable suppression state.
Stable alert hashes support rerun reproducibility. Evidence contains event IDs, not vague strings.

## 3 — Incident correlation and prioritization
Alerts share a component when they share evidence or the same nonempty user and host. IP alone
is deliberately insufficient because NAT would merge unrelated users. A 30-minute total evidence
span bounds each component. This is a deterministic heuristic, not proof of session continuity.
Scoring runs after correlation so combined process and network activity can raise priority.

## 4 — Investigation and presentation
SQLite stores events, alerts and incidents in a single atomic replaceable snapshot. Reruns do not
duplicate records. JSONL exports support inspection. The dashboard reads SQLite directly; FastAPI
offers read-only access for future integrations. Incident timelines contain detection evidence,
not every surrounding benign event. Markdown reports separate observations from hypotheses.

## 5 — Optional AI boundary
AnalystProvider is a typed extension interface; OfflineAnalyst creates deterministic summaries.
There is no key loading, provider call or data transmission today. A future integration must read
keys from the environment, redact telemetry, explicitly obtain data-transfer authorization and
handle timeouts while keeping core detection independent from model availability.

## Data flow and scale
The CLI loads the full input into memory, sorts it, evaluates rules, correlates, then replaces the
snapshot. SQLite and a local UI make this understandable and reproducible. Enterprise scale would
require a queue, partitioned rule state, event-time watermarks, a searchable storage tier,
authenticated analyst access, retention policies and durable case management.
