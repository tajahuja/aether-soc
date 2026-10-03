from hashlib import sha256
from app.config import CORRELATION_SECONDS
from app.models.security import Alert, Event, Incident
from app.scoring.risk import score

def correlate(alerts: list[Alert], events: list[Event]) -> list[Incident]:
    """Connected components link shared evidence or user+host within a bounded span.

    Source IP alone never links incidents: NAT and shared sources are common.
    Each component's evidence span is limited, preventing endless transitive chains.
    """
    lookup = {e.event_id: e for e in events}
    groups: list[list[Alert]] = []
    for current in sorted(alerts, key=lambda a: (a.timestamp, a.alert_id)):
        matches = []
        for group in groups:
            combined = group + [current]
            evidence = [lookup[i] for a in combined for i in a.evidence]
            span = (max(e.timestamp for e in evidence) - min(e.timestamp for e in evidence)).total_seconds()
            related = any(set(current.evidence) & set(a.evidence) or
                          (current.affected_user and current.affected_user == a.affected_user
                           and current.affected_host == a.affected_host) for a in group)
            if related and span <= CORRELATION_SECONDS:
                matches.append(group)
        if matches:
            merged = [current] + [a for g in matches for a in g]
            merged_events = [lookup[i] for a in merged for i in a.evidence]
            if (max(e.timestamp for e in merged_events) - min(e.timestamp for e in merged_events)).total_seconds() <= CORRELATION_SECONDS:
                for group in matches:
                    groups.remove(group)
                groups.append(merged)
            else:
                matches[0].append(current)
        else:
            groups.append([current])
    incidents = []
    for group in groups:
        ids = sorted({i for a in group for i in a.evidence})
        timeline = sorted([lookup[i] for i in ids], key=lambda e: (e.timestamp, e.event_id))
        value, severity, reasons = score(group, timeline)
        techniques = sorted({t for a in group for t in a.mitre})
        key = '|'.join(sorted(a.alert_id for a in group))
        incidents.append(Incident(
            incident_id='INC-' + sha256(key.encode()).hexdigest()[:12],
            title='Correlated activity: ' + ', '.join(sorted({a.rule_name for a in group})),
            severity=severity, risk_score=value, risk_reasons=reasons,
            start_time=timeline[0].timestamp, end_time=timeline[-1].timestamp,
            users=sorted({e.username for e in timeline if e.username}),
            hosts=sorted({e.hostname for e in timeline}),
            ip_addresses=sorted({ip for e in timeline for ip in [e.source_ip, e.destination_ip] if ip}),
            associated_alerts=sorted(a.alert_id for a in group), attack_techniques=techniques,
            timeline=timeline, recommended_actions=sorted({a.recommended_action for a in group})))
    return sorted(incidents, key=lambda i: (-i.risk_score, i.start_time, i.incident_id))
