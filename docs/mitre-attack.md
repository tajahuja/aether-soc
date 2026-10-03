# MITRE ATT&CK coverage

MITRE ATT&CK is a knowledge base of observed adversary behavior. A tactic describes
the objective (why); a technique describes a method (how). Mapping helps analysts
communicate hypotheses, identify coverage gaps and plan additional evidence collection.
Mapping does not prove an attacker used a technique or identify an actor.

Verified against authoritative MITRE pages on 2026-10-03:

| ID | Name | Relevant tactic | AetherSOC evidence |
|---|---|---|---|
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | Credential Access | Repeated authentication failures |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | Initial Access (among other listed tactics) | Success following failures; unusual valid-account use |
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution | PowerShell command-line indicators |

T1110 is used at parent level: multiple accounts alone do not prove password spraying
or password guessing. The outbound alert intentionally has no ATT&CK mapping: connecting
to a lab indicator does not establish application-layer command and control or exfiltration.
The dashboard counts mapped alerts, not confirmed technique execution or coverage completeness.
