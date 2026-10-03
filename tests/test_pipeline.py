import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from streamlit.testing.v1 import AppTest

from app.api import api
from app.config import ROOT
from app.correlation.incidents import correlate
from app.detection.engine import run_rules
from app.ingestion.reader import ingest
from app.models.security import Event
from app.normalization.parsers import normalize
from app.scoring.risk import score
from app.storage import read, save


def event(seconds=0, **kwargs):
    defaults = dict(timestamp=datetime(2026, 1, 15, 10, tzinfo=timezone.utc)
                    + timedelta(seconds=seconds), event_id=f'e-{seconds}',
                    event_type='authentication', hostname='lab-ws', username='lab.user',
                    source_ip='192.0.2.1', status='failure')
    defaults.update(kwargs)
    return Event(**defaults)


def failures():
    return [event(i * 10) for i in range(6)]


def test_windows_parser_preserves_raw_evidence():
    raw = dict(provider='windows', timestamp='2026-01-01T00:00:00Z',
               event_id='windows-4625', event_type='authentication', computer='lab-ws',
               account='lab.user', status='failure')
    parsed = normalize(raw)
    assert parsed.hostname == 'lab-ws'
    assert parsed.username == 'lab.user'
    assert parsed.raw_event == raw


@pytest.mark.parametrize('changes', [dict(timestamp='2026-01-01T00:00:00'),
                                    dict(source_ip='bad-ip'), dict(destination_port=70000)])
def test_invalid_normalization(changes):
    with pytest.raises(ValueError):
        event(**changes)


def test_unknown_source():
    with pytest.raises(ValueError, match='Unsupported provider'):
        normalize({'provider': 'unknown'})


def test_timestamp_is_normalized_to_utc():
    parsed = event(timestamp='2026-01-15T15:30:00+05:30')
    assert parsed.timestamp.hour == 10
    assert parsed.timestamp.utcoffset() == timedelta(0)


def test_ingestion_line_errors(tmp_path):
    path = tmp_path / 'bad.jsonl'
    path.write_text('{bad}\n')
    with pytest.raises(ValueError, match='line 1'):
        ingest(path)


def test_brute_force_threshold_and_deduplication():
    assert not run_rules(failures()[:4])
    alerts = run_rules(failures())
    assert len(alerts) == 1
    assert alerts[0].rule_name == 'Brute Force'
    assert len(alerts[0].evidence) == 5
    assert alerts[0].alert_id == run_rules(list(reversed(failures())))[0].alert_id
    assert alerts[0].mitre == ['T1110']
    assert alerts[0].recommended_action


def test_window_boundary():
    assert not run_rules([event(i * 301) for i in range(5)])
    assert run_rules([event(i * 75) for i in range(5)])


def test_success_matches_account_and_host():
    assert len(run_rules(failures() + [event(70, status='success', username='other')])) == 1
    alerts = run_rules(failures() + [event(70, status='success')])
    assert any(a.rule_name == 'Brute Force Followed by Success' for a in alerts)


def test_multi_account_source():
    alerts = run_rules([event(i, username=f'lab.user{i}') for i in range(4)])
    assert [a.rule_name for a in alerts] == ['Multi-Account Authentication']


@pytest.mark.parametrize('command', ['powershell -enc Zg==',
                                    'powershell -EncodedCommand Zg==',
                                    'powershell -WindowStyle Hidden Get-Date'])
def test_powershell_indicators(command):
    alerts = run_rules([event(event_type='process', process_name='powershell.exe',
                              command_line=command)])
    assert alerts[0].rule_name == 'Suspicious PowerShell'


def test_benign_process_not_detected():
    assert not run_rules([event(event_type='process', process_name='powershell.exe',
                               command_line='Get-Date')])
    assert not run_rules([event(event_type='process', process_name='notepad.exe',
                               command_line='-enc Zg==')])


def test_risk_scoring_is_explainable_and_capped():
    events = failures() + [event(70, status='success', privileged=True),
                           event(80, event_type='process', process_name='powershell.exe',
                                 command_line='-enc Zg=='),
                           event(90, event_type='network', destination_ip='203.0.113.200')]
    value, severity, reasons = score(run_rules(events), events)
    assert value == 100
    assert severity == 'CRITICAL'
    assert any('privileged' in r for r in reasons)
    assert score([], [])[:2] == (0, 'LOW')


def test_correlation_chain_and_shared_ip_separation():
    events = failures() + [event(70, status='success'),
                           event(80, event_type='process', process_name='powershell.exe',
                                 command_line='-enc Zg=='),
                           event(90, event_type='network', destination_ip='203.0.113.200'),
                           event(100, event_type='process', process_name='powershell.exe',
                                 command_line='-enc Zg==', username='other', hostname='other')]
    incidents = correlate(run_rules(events), events)
    assert sorted(len(i.associated_alerts) for i in incidents) == [1, 4]
    chain = max(incidents, key=lambda i: len(i.associated_alerts))
    assert chain.start_time < chain.end_time
    assert {'T1110', 'T1078', 'T1059.001'} == set(chain.attack_techniques)


def test_correlation_does_not_bridge_long_gaps():
    events = [event(t, event_type='process', process_name='powershell.exe',
                    command_line='-enc Zg==') for t in [0, 1700, 3400]]
    assert len(correlate(run_rules(events), events)) == 2


def test_storage_snapshot_idempotence(tmp_path):
    events = failures()
    alerts = run_rules(events)
    incidents = correlate(alerts, events)
    path = tmp_path / 'soc.db'
    save(events, alerts, incidents, path)
    save(events, alerts, incidents, path)
    assert len(read('events', path)) == 6
    assert len(read('incidents', path)) == 1


def test_complete_seeded_demo_scenarios():
    events = ingest(ROOT / 'data/raw/events.jsonl')
    labels = json.loads((ROOT / 'data/synthetic/labels.json').read_text())
    alerts = run_rules(events)
    observed = {labels[e] for a in alerts for e in a.evidence}
    assert {'1', '2', '3', '4', '5'} <= observed
    assert len(events) == 1222
    assert len(alerts) == 9
    assert len(correlate(alerts, events)) == 5
    assert not any(labels[e] == 'benign' for a in alerts for e in a.evidence)


def test_api_routes():
    client = TestClient(api)
    assert client.get('/health').json()['status'] == 'ok'
    incidents = client.get('/incidents').json()
    assert len(incidents) == 5
    assert client.get('/incidents/' + incidents[0]['incident_id']).status_code == 200
    assert client.get('/incidents/missing').status_code == 404


def test_dashboard_render_and_incident_selection():
    dashboard = AppTest.from_file(str(ROOT / 'dashboard/app.py')).run(timeout=30)
    assert not dashboard.exception
    assert len(dashboard.metric) == 5
    assert dashboard.metric[0].value == '1222'
    dashboard.selectbox[0].select_index(1).run(timeout=30)
    assert not dashboard.exception
