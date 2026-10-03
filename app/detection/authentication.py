from collections import defaultdict, deque
from app.config import AUTH_WINDOW_SECONDS, FAILURE_THRESHOLD, MULTI_ACCOUNT_THRESHOLD
from app.detection.base import alert
from app.models.security import Alert, Event

def detect(events: list[Event]) -> list[Alert]:
    windows = defaultdict(deque)
    emitted = set()
    results = []
    for event in events:
        if event.event_type != 'authentication' or not event.source_ip:
            continue
        window = windows[event.source_ip]
        while window and (event.timestamp - window[0].timestamp).total_seconds() > AUTH_WINDOW_SECONDS:
            window.popleft()
        if event.status == 'failure':
            window.append(event)
            checks = [
                ('Brute Force', len(window) >= FAILURE_THRESHOLD, 'T1110'),
                ('Multi-Account Authentication',
                 len({e.username for e in window if e.username}) >= MULTI_ACCOUNT_THRESHOLD,
                 'T1110')]
            for name, matches, technique in checks:
                # One alert per source burst. A quiet gap resets the burst key.
                key = (name, event.source_ip, window[0].event_id)
                if matches and key not in emitted:
                    results.append(alert(name, list(window), 'HIGH',
                                         'Authentication failures exceeded a rolling-window threshold.',
                                         [technique], 'Validate source ownership and review authentication history.'))
                    emitted.add(key)
        elif event.status == 'success':
            matching = [e for e in window if e.username == event.username
                        and e.hostname == event.hostname]
            if len(matching) >= FAILURE_THRESHOLD:
                results.append(alert('Brute Force Followed by Success', matching + [event],
                                     'CRITICAL', 'Success followed failures for the same source, user and host.',
                                     ['T1110', 'T1078'],
                                     'Verify with the account owner; revoke sessions if compromise is confirmed.'))
                window.clear()
    return results
