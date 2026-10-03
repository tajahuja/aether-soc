import argparse
import logging
from pathlib import Path
from app.config import ROOT
from app.ingestion.reader import ingest
from app.detection.engine import run_rules
from app.correlation.incidents import correlate
from app.storage import save
from app.reporting.markdown import report

def analyze(path: Path):
    events = ingest(path)
    alerts = run_rules(events)
    incidents = correlate(alerts, events)
    save(events, alerts, incidents)
    processed = ROOT / 'data/processed'
    for name, objects in [('events', events), ('alerts', alerts), ('incidents', incidents)]:
        (processed / f'{name}.jsonl').write_text(
            '\n'.join(o.model_dump_json() for o in objects)+'\n', encoding='utf-8')
    output = ROOT / 'reports/generated'
    output.mkdir(parents=True, exist_ok=True)
    for incident in incidents:
        (output / f'{incident.incident_id}.md').write_text(report(incident), encoding='utf-8')
    logging.info('%s events, %s alerts, %s incidents', len(events), len(alerts), len(incidents))
    return events, alerts, incidents

def main():
    parser = argparse.ArgumentParser(description='AetherSOC local analysis')
    parser.add_argument('command', choices=['demo', 'analyze'])
    parser.add_argument('--input', type=Path, default=ROOT / 'data/raw/events.jsonl')
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    if args.command == 'demo':
        from scripts.generate_data import generate
        args.input = generate()
    analyze(args.input)

if __name__ == '__main__':
    main()
