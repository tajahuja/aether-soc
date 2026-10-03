# Local validation

Validated on Windows with Python 3.12.14 on 2026-10-03.

- Installed pinned direct dependencies in `.venv` and froze the tested full environment.
- `pip check`: no broken requirements.
- Seed-42 demo: 1,222 normalized events, 9 alerts, 5 incidents.
- Main case `INC-b06a7a636c3c`: four alerts, ten evidence events, risk 100/100.
- Every labeled scenario class 1–5 contributes detection evidence; no benign seed-42
  event appears in an alert. This is fixture coverage, not a real-world false-positive rate.
- pytest: 22 passing tests after the UTC normalization regression test was added.
- Ruff: all checks pass.
- Streamlit AppTest rendered KPIs, charts and incident details, then changed incident selection
  without an exception.
- `python -m scripts.validate_servers` started real Streamlit and FastAPI child processes,
  verified dashboard HTTP readiness and API alert/incident counts, then stopped those validation servers.

Two dependency deprecation warnings remain (Starlette/AnyIO and Streamlit/Altair).
They do not fail these tests; dependency upgrades should be tested rather than hidden.

The tool execution environment isolates local server processes from separate shell/browser calls.
Live HTTP validation therefore ran in the same process context as its child servers.
The in-app browser navigation timed out; no visual browser screenshot is claimed.
The README intentionally includes screenshot placeholders.

The VS Code command wrapper failed with a permission error; direct Code.exe was invoked,
but opening the visible VS Code workspace could not be confirmed. Open the project using
VS Code's File > Open Folder, then run the README commands in its terminal.

For restricted temporary directories, run tests with workspace-local temporary storage:

```powershell
New-Item -ItemType Directory -Force .test-work | Out-Null
$env:TEMP = (Resolve-Path .test-work).Path
$env:TMP = $env:TEMP
.\.venv\Scripts\python.exe -m app.cli demo
.\.venv\Scripts\python.exe -m pytest -q
```

No GitHub push, production deployment, real attack, scan or real telemetry ingestion occurred.
Local commits use a clearly labeled builder identity rather than impersonating the user.
