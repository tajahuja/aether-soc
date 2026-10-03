# Interview guide

**What problem does your SOC solve?** It turns noisy synthetic endpoint logs into evidence-backed
alerts and related investigation cases so an analyst can prioritize and explain activity.

**How does brute-force detection work?** A source-IP deque holds failed authentication events
within 300 seconds. Five failures produce an alert. A subsequent success requires the same
source, account and host to create the higher-priority follow-on detection.

**Why use a time window?** Five failures in five minutes mean something different from five over
a month. The rolling window bounds state and makes the threshold operationally meaningful.

**What causes false positives?** Password typos, scheduled scripts, shared egress IPs, VPN changes,
on-call administrators and approved PowerShell automation. Lab thresholds are not universal.

**What is event correlation?** Linking alerts using shared evidence or matching account/host
within a bounded time span. In my project this produces one case from a multi-stage sequence.
It provides context, not proof that one attacker caused every event.

**What is a SIEM?** Security Information and Event Management centralizes telemetry for search,
detection and investigation. AetherSOC demonstrates a small part of that workflow locally.

**What is MITRE ATT&CK?** A behavioral knowledge base. Tactics describe goals, techniques methods.
I use T1110, T1078 and T1059.001, verified against MITRE, without claiming confirmed compromise.

**Event versus alert versus incident?** An event is a recorded observation. An alert is a rule's
finding with evidence. An incident is a related collection prioritized for investigation.

**How does your risk score work?** Highest alert severity contributes 10–60 points, additional
evidence up to 10, privileged involvement 10, success after failures 10, PowerShell 10 and
suspicious outbound activity 5. It caps at 100 and displays each contribution.

**How would this change at enterprise scale?** Replace batch memory and local SQLite with
streaming ingestion, partitioned state, searchable storage, event-time handling, retention,
access controls, case management and monitored rule deployment.

**How would Splunk, Sentinel or Elastic fit?** They could replace ingestion, search and dashboard
layers. I would translate rule semantics into their query languages, map normalized fields,
test correlation windows and preserve evidence IDs. Sigma can help port rule intent.

**How would you reduce false positives?** Measure alerts against labeled outcomes, baseline user
and host behavior, enrich asset roles and change tickets, and add narrow documented allowlists.
Do not broadly exclude all administrators or all PowerShell.

**How would you respond?** Validate owner activity, inspect endpoint/process and authentication
evidence, preserve artifacts, scope affected accounts and hosts, then recommend approved
containment if compromise is confirmed. The tool does not automate response.

**Is this really AI powered?** The current analyst is deterministic and offline. I built a typed
provider boundary for an optional future LLM, but no hosted model is connected or required.

**How did you validate it?** Seeded data contains five scenario classes plus benign background.
Tests check positive and negative inputs, timing edges, separation, persistence, API and UI.
Passing synthetic tests does not establish real-world detection accuracy.

**What is the biggest limitation?** Correlation has no session IDs and the lab has no real telemetry.
I would add representative data, baselines, durable suppression and analyst evaluation next.
