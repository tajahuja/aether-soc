"""Source adapters isolate vendor field names from behavioral detections."""
from app.models.security import Event

def parse_windows(raw: dict) -> Event:
    fields = dict(raw)
    fields.pop('provider', None)
    fields['hostname'] = fields.pop('computer')
    fields['username'] = fields.pop('account', '')
    fields['raw_event'] = raw
    return Event.model_validate(fields)

def parse_sensor(raw: dict) -> Event:
    fields = {k: v for k, v in raw.items() if k != 'provider'}
    fields['raw_event'] = raw
    return Event.model_validate(fields)

PARSERS = {'windows': parse_windows, 'sensor': parse_sensor}

def normalize(raw: dict) -> Event:
    provider = raw.get('provider')
    if provider not in PARSERS:
        raise ValueError(f'Unsupported provider: {provider}')
    return PARSERS[provider](raw)
