from datetime import datetime
from ipaddress import ip_address
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator

Severity = Literal['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

class Event(BaseModel):
    timestamp: datetime
    event_id: str
    event_type: Literal['authentication', 'process', 'dns', 'network', 'firewall', 'endpoint']
    hostname: str
    username: str = ''
    source_ip: str = ''
    destination_ip: str = ''
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str = ''
    process_name: str = ''
    command_line: str = ''
    action: str = ''
    status: str = ''
    severity: Severity = 'LOW'
    privileged: bool = False
    site: str = ''
    domain: str = ''
    raw_event: dict[str, Any] = Field(default_factory=dict)

    @field_validator('timestamp')
    @classmethod
    def aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('timestamp must include a timezone')
        return value

    @field_validator('source_ip', 'destination_ip')
    @classmethod
    def valid_ip(cls, value: str) -> str:
        if value:
            ip_address(value)
        return value

class Alert(BaseModel):
    alert_id: str
    timestamp: datetime
    rule_name: str
    description: str
    severity: Severity
    affected_host: str
    affected_user: str
    source: str
    evidence: list[str]
    mitre: list[str]
    recommended_action: str

class Incident(BaseModel):
    incident_id: str
    title: str
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    risk_reasons: list[str]
    start_time: datetime
    end_time: datetime
    users: list[str]
    hosts: list[str]
    ip_addresses: list[str]
    associated_alerts: list[str]
    attack_techniques: list[str]
    timeline: list[Event]
    recommended_actions: list[str]
    status: Literal['OPEN', 'CLOSED'] = 'OPEN'
