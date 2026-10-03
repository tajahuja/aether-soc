import re
from app.detection.base import alert
from app.models.security import Alert, Event

PATTERN = re.compile(r'(?i)(?:^|\s)-(?:enc(?:odedcommand)?|w(?:indowstyle)?\s+hidden)(?:\s|$)|downloadstring|invoke-expression')

def detect(events: list[Event]) -> list[Alert]:
    return [alert('Suspicious PowerShell', [e], 'HIGH',
                  'PowerShell command line contains an encoded, hidden or download/execute indicator.',
                  ['T1059.001'], 'Review script content and parent process; confirm approved automation.')
            for e in events if e.event_type == 'process'
            and e.process_name.lower() in {'powershell.exe', 'pwsh.exe'}
            and PATTERN.search(e.command_line)]
