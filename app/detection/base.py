from hashlib import sha256
from app.models.security import Alert, Event, Severity

def alert(name: str, evidence: list[Event], severity: Severity,
          description: str, mitre: list[str], action: str) -> Alert:
    ordered = sorted(evidence, key=lambda e: (e.timestamp, e.event_id))
    last = ordered[-1]
    key = name + '|' + '|'.join(e.event_id for e in ordered)
    return Alert(alert_id='ALT-' + sha256(key.encode()).hexdigest()[:12],
                 timestamp=last.timestamp, rule_name=name, description=description,
                 severity=severity, affected_host=last.hostname,
                 affected_user=last.username, source=last.source_ip,
                 evidence=[e.event_id for e in ordered], mitre=mitre,
                 recommended_action=action)
