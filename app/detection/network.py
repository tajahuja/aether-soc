from app.config import SUSPICIOUS_DESTINATIONS, CORRELATION_SECONDS
from app.detection.base import alert
from app.models.security import Alert, Event

def detect(events: list[Event]) -> list[Alert]:
    results = []
    privileged = {}
    for e in events:
        key = (e.hostname, e.username)
        if e.event_type == 'authentication' and e.status == 'success' and e.privileged:
            privileged[key] = e
        if e.event_type != 'network' or e.destination_ip not in SUSPICIOUS_DESTINATIONS:
            continue
        prior = privileged.get(key)
        evidence = [e]
        if prior and (e.timestamp - prior.timestamp).total_seconds() <= CORRELATION_SECONDS:
            evidence.insert(0, prior)
        results.append(alert('Suspicious Outbound Connection', evidence,
                             'HIGH' if len(evidence) > 1 else 'MEDIUM',
                             'Connection to a configured lab indicator' +
                             (' after privileged authentication.' if len(evidence) > 1 else '.'),
                             [], 'Review destination, process and proxy evidence before blocking.'))
    return results
