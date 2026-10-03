from app.models.security import Alert, Event, Severity

BASE = {'LOW': 10, 'MEDIUM': 25, 'HIGH': 45, 'CRITICAL': 60}

def score(alerts: list[Alert], events: list[Event]) -> tuple[int, Severity, list[str]]:
    if not alerts:
        return 0, 'LOW', ['No detections: 0']
    base = max(BASE[a.severity] for a in alerts)
    reasons = [f'+{base} highest alert severity']
    total = base
    factors = [
        (min(10, max(0, len({e.event_id for e in events}) - 1)), 'additional evidence events (cap 10)'),
        (10 if any(e.privileged for e in events) else 0, 'privileged account involvement'),
        (10 if any(a.rule_name == 'Brute Force Followed by Success' for a in alerts) else 0,
         'successful authentication after failures'),
        (10 if any(a.rule_name == 'Suspicious PowerShell' for a in alerts) else 0,
         'suspicious PowerShell'),
        (5 if any(a.rule_name == 'Suspicious Outbound Connection' for a in alerts) else 0,
         'suspicious outbound activity')]
    for points, reason in factors:
        if points:
            total += points
            reasons.append(f'+{points} {reason}')
    total = min(100, total)
    severity = 'CRITICAL' if total >= 85 else 'HIGH' if total >= 60 else 'MEDIUM' if total >= 30 else 'LOW'
    reasons.append('Final score capped at 100; prioritization heuristic, not compromise probability.')
    return total, severity, reasons
