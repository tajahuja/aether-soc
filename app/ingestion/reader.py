import json
from pathlib import Path
from app.normalization.parsers import normalize
from app.models.security import Event

def ingest(path: Path) -> list[Event]:
    """Reject malformed input with a line number; deduplicate exact event IDs."""
    events: dict[str, Event] = {}
    for line_number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            event = normalize(json.loads(line))
            if event.event_id in events and events[event.event_id] != event:
                raise ValueError('Conflicting duplicate event ID')
            events[event.event_id] = event
        except (ValueError, KeyError, TypeError) as exc:
            raise ValueError(f'{path.name}, line {line_number}: {exc}') from exc
    return sorted(events.values(), key=lambda e: (e.timestamp, e.event_id))
