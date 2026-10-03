"""Launch actual HTTP servers and verify them from the same local process context."""
import json
import subprocess
import sys
import time
from urllib.request import urlopen

from app.config import ROOT


def wait_for(url: str) -> bytes:
    last_error = None
    for _ in range(40):
        try:
            with urlopen(url, timeout=1) as response:
                return response.read()
        except OSError as exc:
            last_error = exc
            time.sleep(0.25)
    raise RuntimeError(f'Server did not become ready: {url}') from last_error


def main():
    processes = []
    try:
        commands = [
            [sys.executable, '-m', 'streamlit', 'run', 'dashboard/app.py',
             '--server.address', '127.0.0.1', '--server.port', '8502',
             '--server.headless', 'true', '--browser.gatherUsageStats', 'false'],
            [sys.executable, '-m', 'uvicorn', 'app.api:api', '--host', '127.0.0.1',
             '--port', '8001'],
        ]
        for command in commands:
            processes.append(subprocess.Popen(command, cwd=ROOT, stdout=subprocess.DEVNULL,
                                              stderr=subprocess.DEVNULL))
        assert wait_for('http://127.0.0.1:8502/_stcore/health') == b'ok'
        page = wait_for('http://127.0.0.1:8502/').decode()
        assert '<html' in page.lower()
        assert json.loads(wait_for('http://127.0.0.1:8001/health'))['status'] == 'ok'
        assert len(json.loads(wait_for('http://127.0.0.1:8001/alerts'))) == 9
        assert len(json.loads(wait_for('http://127.0.0.1:8001/incidents'))) == 5
        print('Live Streamlit and FastAPI HTTP checks passed; 9 alerts, 5 incidents.')
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=10)


if __name__ == '__main__':
    main()
