# Investigation: INC-b06a7a636c3c

## Executive Summary
INC-b06a7a636c3c: 4 alerts, 100/100 priority. Review the timeline, validate account owner activity and seek corroborating endpoint evidence. This deterministic summary does not establish compromise. All evidence is synthetic.

## Incident Description
Correlated activity: Brute Force, Brute Force Followed by Success, Suspicious Outbound Connection, Suspicious PowerShell. Alerts indicate behavior needing review; they do not prove account compromise.

## Timeline
| UTC time | Event | Type | Host | User | Result |
|---|---|---|---|---|---|
| 2026-01-15T10:01:00+00:00 | EVT-01201 | authentication | lab-ws-01 | lab.admin | failure |
| 2026-01-15T10:01:15+00:00 | EVT-01202 | authentication | lab-ws-01 | lab.admin | failure |
| 2026-01-15T10:01:30+00:00 | EVT-01203 | authentication | lab-ws-01 | lab.admin | failure |
| 2026-01-15T10:01:45+00:00 | EVT-01204 | authentication | lab-ws-01 | lab.admin | failure |
| 2026-01-15T10:02:00+00:00 | EVT-01205 | authentication | lab-ws-01 | lab.admin | failure |
| 2026-01-15T10:02:15+00:00 | EVT-01206 | authentication | lab-ws-01 | lab.admin | failure |
| 2026-01-15T10:02:30+00:00 | EVT-01207 | authentication | lab-ws-01 | lab.admin | failure |
| 2026-01-15T10:03:00+00:00 | EVT-01208 | authentication | lab-ws-01 | lab.admin | success |
| 2026-01-15T10:03:30+00:00 | EVT-01209 | process | lab-ws-01 | lab.admin | success |
| 2026-01-15T10:04:00+00:00 | EVT-01210 | network | lab-ws-01 | lab.admin | success |

## Evidence
- `EVT-01201`: source `192.0.2.200`, destination ``, process ``, command ``.
- `EVT-01202`: source `192.0.2.200`, destination ``, process ``, command ``.
- `EVT-01203`: source `192.0.2.200`, destination ``, process ``, command ``.
- `EVT-01204`: source `192.0.2.200`, destination ``, process ``, command ``.
- `EVT-01205`: source `192.0.2.200`, destination ``, process ``, command ``.
- `EVT-01206`: source `192.0.2.200`, destination ``, process ``, command ``.
- `EVT-01207`: source `192.0.2.200`, destination ``, process ``, command ``.
- `EVT-01208`: source `192.0.2.200`, destination ``, process ``, command ``.
- `EVT-01209`: source `192.0.2.200`, destination ``, process `powershell.exe`, command `powershell.exe -EncodedCommand RwBlAHQALQBEAGEAdABlAA==`.
- `EVT-01210`: source `192.0.2.200`, destination `203.0.113.200`, process ``, command ``.

## Indicators
Documentation-only IP addresses: 192.0.2.200, 203.0.113.200.

## Affected Assets
Hosts: lab-ws-01. Users: lab.admin.

## MITRE ATT&CK Mapping
T1059.001, T1078, T1110
These are behavioral hypotheses, not confirmed adversary attribution.

## Risk Assessment
100/100 (CRITICAL).
- +60 highest alert severity
- +9 additional evidence events (cap 10)
- +10 privileged account involvement
- +10 successful authentication after failures
- +10 suspicious PowerShell
- +5 suspicious outbound activity
- Final score capped at 100; prioritization heuristic, not compromise probability.

## Observations and Assumptions
Observed: the listed timestamps, authentication results, command-line strings and connections.
Assumed: the activities may share an operator. Correlation is temporal and entity-based;
there is no session ID, real geolocation, payload execution or proof of data theft.

## Containment Recommendations
Validate account owner activity and collect endpoint evidence. If compromise is confirmed,
revoke sessions, restrict the account and isolate the endpoint under approved procedures.

## Eradication Recommendations
Investigate persistence and remove confirmed unauthorized artifacts. No remediation is automated.

## Recovery Recommendations
Rotate affected credentials after scope confirmation, restore verified configurations,
and monitor for recurrence before returning the endpoint to normal access.

## Lessons Learned
Tune thresholds against legitimate automation. Add session IDs, asset criticality and
baseline enrichment. Preserve evidence before changing assets.
