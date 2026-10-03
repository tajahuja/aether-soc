# Five-minute recruiter walkthrough

1. Regenerate with `python -m app.cli demo` using the project virtual environment.
2. Start Streamlit and show 1,222 events, nine alerts and five incidents.
3. Explain that most telemetry is benign and labels are not used by detections.
4. Select the lab.admin incident. Read the sequence: failures at 10:01 UTC onward,
   success at 10:03, PowerShell at 10:03:30 and network connection at 10:04.
5. Expand raw evidence. Explain an event, an alert, and the correlated incident.
6. Show score reasons: highest rule severity, evidence count, privilege, success,
   process and network factors. State that priority is not a compromise probability.
7. Point out verified ATT&CK IDs and why the network alert has no speculative mapping.
8. Download the report and explain evidence versus assumptions and conditional response.
9. Finish with tests and limitations: synthetic batch data, no session proof or real-world accuracy.

Understand these five files first: `scripts/generate_data.py`, `app/models/security.py`,
`app/detection/authentication.py`, `app/correlation/incidents.py`, `app/scoring/risk.py`.
Then explore the dashboard and reporting module to see how findings become analyst decisions.
