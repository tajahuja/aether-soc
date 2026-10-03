from app.detection import authentication, identity, network, process
from app.models.security import Alert, Event

def run_rules(events: list[Event]) -> list[Alert]:
    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    alerts = [a for rule in (authentication, process, identity, network) for a in rule.detect(ordered)]
    return sorted({a.alert_id: a for a in alerts}.values(), key=lambda a: (a.timestamp, a.alert_id))
