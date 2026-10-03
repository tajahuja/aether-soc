"""Seeded synthetic telemetry; no network calls or command execution."""
import json
import random
from datetime import datetime, timedelta, timezone
from app.config import ROOT

def generate(seed=42):
    rng = random.Random(seed)
    base = datetime(2026, 1, 15, 10, tzinfo=timezone.utc)
    records = []
    labels = {}
    def add(seconds, kind='authentication', user='lab.aria', host='lab-ws-01',
            source='192.0.2.10', status='success', scenario='benign', **extra):
        event_id = f'EVT-{len(records)+1:05d}'
        windows = kind in {'authentication', 'process'}
        raw = dict(provider='windows' if windows else 'sensor',
                   timestamp=(base + timedelta(seconds=seconds)).isoformat(), event_id=event_id,
                   event_type=kind, source_ip=source, status=status, **extra)
        raw['computer' if windows else 'hostname'] = host
        raw['account' if windows else 'username'] = user
        records.append(raw)
        labels[event_id] = scenario
        return event_id
    for i in range(1200):
        kind = rng.choice(['authentication','authentication','process','dns','network','firewall','endpoint'])
        user_index = rng.randrange(12)
        extra = {}
        if kind == 'process':
            extra = dict(process_name=rng.choice(['explorer.exe','powershell.exe','notepad.exe']),
                         command_line='Get-Date')
        elif kind == 'dns':
            extra = dict(domain='portal.example.test', action='query')
        elif kind in {'network', 'firewall'}:
            extra = dict(destination_ip='198.51.100.20', destination_port=443,
                         source_port=50000+i, protocol='TCP', action='allow')
        elif kind == 'endpoint':
            extra = dict(action='health_check')
        add(rng.randrange(28800), kind, f'lab.user{user_index}', f'lab-ws-{user_index+10}',
            f'192.0.2.{user_index+30}', 'failure' if kind == 'authentication' and rng.random()<0.04 else 'success', **extra)
    # Scenario 1 and 5 form the recruiter demonstration chain.
    for i in range(7):
        add(60+i*15, user='lab.admin', source='192.0.2.200', status='failure', scenario='1')
    add(180, user='lab.admin', source='192.0.2.200', privileged=True, scenario='1')
    add(210, 'process', 'lab.admin', source='192.0.2.200', scenario='2',
        process_name='powershell.exe', command_line='powershell.exe -EncodedCommand RwBlAHQALQBEAGEAdABlAA==')
    add(240, 'network', 'lab.admin', source='192.0.2.200', scenario='5',
        destination_ip='203.0.113.200', destination_port=443, protocol='TCP', action='connect')
    add(4000, 'process', 'lab.mira', 'lab-ws-02', scenario='2',
        process_name='powershell.exe', command_line='powershell.exe -WindowStyle Hidden Get-Date')
    add(5000, user='lab.nova', host='lab-ws-03', site='lab-east', scenario='3')
    add(5060, user='lab.nova', host='lab-ws-03', source='198.51.100.80', site='lab-west', scenario='3')
    for i in range(6):
        add(6000+i*20, user=f'lab.target{i}', host='lab-ws-04', source='192.0.2.201', status='failure', scenario='4')
    add(-7200, user='lab.ops-admin', host='lab-ws-05', privileged=True, scenario='privileged')
    add(9000, user='lab.ops-admin', host='lab-ws-05', privileged=True, scenario='5')
    add(9050, 'network', 'lab.ops-admin', 'lab-ws-05', scenario='5',
        destination_ip='203.0.113.200', destination_port=8443, action='connect')
    raw_path = ROOT / 'data/raw/events.jsonl'
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text('\n'.join(json.dumps(r) for r in records)+'\n', encoding='utf-8')
    label_path = ROOT / 'data/synthetic/labels.json'
    label_path.parent.mkdir(parents=True, exist_ok=True)
    label_path.write_text(json.dumps(labels, indent=2), encoding='utf-8')
    return raw_path

if __name__ == '__main__':
    print(generate())
