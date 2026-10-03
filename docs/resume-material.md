# Truthful resume and interview material

## Three resume bullet options

- Built AetherSOC, a local Python SOC lab normalizing 1,222 synthetic events into seven behavioral detection types, evidence-backed alerts and correlated incidents.
- Implemented rolling-window authentication detections, PowerShell indicators and explainable risk scoring, with MITRE ATT&CK mappings and automated positive/negative tests.
- Developed a Streamlit investigation dashboard, SQLite persistence, read-only FastAPI endpoints and Markdown incident reports demonstrating a synthetic multi-stage authentication-to-network sequence.

Use one or two bullets appropriate to the role; do not imply production deployment or real incidents.

## 30-second explanation

I built AetherSOC to learn how a SOC turns logs into investigations. It generates realistic synthetic
telemetry, normalizes it and evaluates seven detection types. I correlate related alerts, calculate
an explainable priority score and show the evidence in a Streamlit dashboard. My main demo follows
failed logins through successful authentication, suspicious PowerShell and outbound activity.

## 60-second explanation

AetherSOC is my defensive SOC portfolio lab. I wanted to understand the difference between detecting
one event and investigating a sequence. I used Python and Pydantic for normalization, modular rules
for authentication, processes, identity and network activity, and SQLite for local persistence.
The seeded dataset contains 1,200 benign events plus labeled scenario events. The default run yields
nine alerts and five incidents. Correlation uses shared evidence or matching user and host within
30 minutes, and the score exposes each contribution. I mapped supported behaviors to MITRE ATT&CK,
built an investigation dashboard and tested timing boundaries and false-positive inputs. It is an
educational batch system with an offline analyst interface, not a production SIEM or a deployed LLM.

## LinkedIn project description

Built AetherSOC, a local defensive cybersecurity lab exploring the journey from security telemetry
to analyst investigation. The project includes synthetic Windows and sensor logs, modular behavioral
detections, MITRE ATT&CK mapping, explainable risk scoring, correlated incidents and a Streamlit
dashboard with downloadable investigation reports. Automated tests cover rule behavior and the
analysis workflow. The project uses only fictional sample data and does not perform attacks or scans.
My next steps are baseline tuning, session-aware correlation and a carefully scoped optional AI provider.
