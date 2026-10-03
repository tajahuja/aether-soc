from app.models.security import Incident
from app.ai.analyst import OfflineAnalyst

def report(incident: Incident) -> str:
    rows = '\n'.join(f'| {e.timestamp.isoformat()} | {e.event_id} | {e.event_type} | {e.hostname} | {e.username} | {e.status or e.action} |'
                     for e in incident.timeline)
    evidence = '\n'.join(f'- `{e.event_id}`: source `{e.source_ip}`, destination `{e.destination_ip}`, '
                         f'process `{e.process_name}`, command `{e.command_line}`.' for e in incident.timeline)
    return f"""# Investigation: {incident.incident_id}

## Executive Summary
{OfflineAnalyst().summarize(incident)} All evidence is synthetic.

## Incident Description
{incident.title}. Alerts indicate behavior needing review; they do not prove account compromise.

## Timeline
| UTC time | Event | Type | Host | User | Result |
|---|---|---|---|---|---|
{rows}

## Evidence
{evidence}

## Indicators
Documentation-only IP addresses: {', '.join(incident.ip_addresses)}.

## Affected Assets
Hosts: {', '.join(incident.hosts)}. Users: {', '.join(incident.users)}.

## MITRE ATT&CK Mapping
{', '.join(incident.attack_techniques) or 'No supported technique mapping.'}
These are behavioral hypotheses, not confirmed adversary attribution.

## Risk Assessment
{incident.risk_score}/100 ({incident.severity}).
""" + '\n'.join('- ' + reason for reason in incident.risk_reasons) + """

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
"""
