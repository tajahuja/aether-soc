# Explainable risk scoring

The score is a prioritization heuristic, not a probability or machine-learning prediction.
Each factor is counted once per incident, except bounded evidence count.

| Factor | Points |
|---|---:|
| Highest alert severity LOW / MEDIUM / HIGH / CRITICAL | 10 / 25 / 45 / 60 |
| Unique evidence events beyond the first | 1 each, maximum 10 |
| Any privileged event | 10 |
| Brute Force Followed by Success alert | 10 |
| Suspicious PowerShell alert | 10 |
| Suspicious Outbound Connection alert | 5 |

Sum the contributions, then cap at 100. Incident severity is LOW below 30,
MEDIUM 30–59, HIGH 60–84, CRITICAL 85–100. An incident's severity can differ
from an individual alert's severity. No alerts returns 0/LOW.

The main incident has 10 unique evidence events: 60 + 9 + 10 + 10 + 10 + 5 = 104,
capped at 100. The seven failures add context even though the first threshold alert
fires on the fifth failure. Rules and scoring share evidence without double-counting event IDs.
Weights are explicit lab choices; validate them against analyst outcomes before real use.
