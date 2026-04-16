"""Local dashboard server — serves the pre-built Next.js dashboard via subprocess."""
import os, subprocess, sys, webbrowser, time, threading
from pathlib import Path

DASHBOARD_DIR = Path(__file__).parent.parent / "dashboard"
NEXT_BUILD_DIR = DASHBOARD_DIR / ".next"

def is_dashboard_built() -> bool:
    """Return True if the Next.js build exists."""
    return (NEXT_BUILD_DIR / "BUILD_ID").exists()

def start_dashboard(
    port: int = 4000,
    auto_open: bool = True,
    report_path: str | None = None,
    blocking: bool = False,
) -> subprocess.Popen | None:
    """
    Start the Next.js dashboard server.

    If not built, runs `npm run build` first (with status output).
    Then runs `npm start` in DASHBOARD_DIR.

    Sets SENTINEL_REPORT_PATH env var so the API route finds findings.json.

    If auto_open: waits up to 5s for port to be listening, then opens browser.

    If blocking: waits for process to terminate (for `sentinel dashboard` command).
    Returns Popen handle (or None if dashboard dir not found).
    """
    if not DASHBOARD_DIR.exists():
        print(f"Dashboard not found at {DASHBOARD_DIR}. Run: pip install sentinel-sec[dashboard]",
              file=sys.stderr)
        return None

    env = {**os.environ}
    if report_path:
        env["SENTINEL_REPORT_PATH"] = report_path
    env["PORT"] = str(port)

    if not is_dashboard_built():
        print("Building dashboard (first run only)...")
        subprocess.run(["npm", "run", "build"], cwd=DASHBOARD_DIR, check=True, env=env)

    proc = subprocess.Popen(
        ["npm", "start"],
        cwd=DASHBOARD_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if auto_open:
        def _open():
            # Poll until port is open (max 8s)
            import socket
            for _ in range(16):
                time.sleep(0.5)
                try:
                    with socket.create_connection(("localhost", port), timeout=0.5):
                        break
                except OSError:
                    pass
            webbrowser.open(f"http://localhost:{port}")
        threading.Thread(target=_open, daemon=True).start()

    if blocking:
        try:
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()

    return proc
