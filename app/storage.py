import json
import sqlite3
from app.config import DB_PATH

def connect(path=DB_PATH):
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute('CREATE TABLE IF NOT EXISTS objects (kind TEXT, id TEXT, payload TEXT, PRIMARY KEY(kind,id))')
    return connection

def save(events, alerts, incidents, path=DB_PATH):
    """Atomically replace one complete local analysis snapshot; safe to rerun."""
    with connect(path) as connection:
        connection.execute('DELETE FROM objects')
        for kind, objects, identifier in [('events', events, 'event_id'),
                                           ('alerts', alerts, 'alert_id'),
                                           ('incidents', incidents, 'incident_id')]:
            connection.executemany('INSERT INTO objects VALUES (?,?,?)',
                                   [(kind, getattr(o, identifier), o.model_dump_json()) for o in objects])

def read(kind, path=DB_PATH):
    with connect(path) as connection:
        return [json.loads(row[0]) for row in connection.execute(
            'SELECT payload FROM objects WHERE kind=? ORDER BY id', (kind,))]
