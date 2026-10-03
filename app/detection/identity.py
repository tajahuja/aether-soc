from app.config import UNUSUAL_LOGIN_SECONDS
from app.detection.base import alert
from app.models.security import Alert, Event

def detect(events: list[Event]) -> list[Alert]:
    results = []
    previous = {}
    for e in events:
        if e.event_type != 'authentication' or e.status != 'success':
            continue
        if e.privileged and (e.timestamp.hour < 8 or e.timestamp.hour >= 18):
            results.append(alert('Unusual Privileged Login', [e], 'MEDIUM',
                                 'Privileged login outside the lab UTC working hours (08:00-18:00).',
                                 ['T1078'], 'Check change tickets, on-call schedules and source ownership.'))
        last = previous.get(e.username)
        if last and last.site and e.site and last.site != e.site and (
            e.timestamp - last.timestamp).total_seconds() <= UNUSUAL_LOGIN_SECONDS:
            results.append(alert('Unusual Login Location', [last, e], 'HIGH',
                                 'Same account authenticated at two synthetic sites within two minutes.',
                                 ['T1078'], 'Check VPN and shared account use; validate both sessions.'))
        previous[e.username] = e
    return results
