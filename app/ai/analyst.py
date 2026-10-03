"""Offline default and replaceable provider protocol. Never transmits telemetry."""
from typing import Protocol
from app.models.security import Incident

class AnalystProvider(Protocol):
    def summarize(self, incident: Incident) -> str: ...

class OfflineAnalyst:
    def summarize(self, incident: Incident) -> str:
        return (f'{incident.incident_id}: {len(incident.associated_alerts)} alerts, '
                f'{incident.risk_score}/100 priority. Review the timeline, validate account '
                'owner activity and seek corroborating endpoint evidence. '
                'This deterministic summary does not establish compromise.')
