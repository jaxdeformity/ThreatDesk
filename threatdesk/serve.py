"""``threatdesk`` entry point: serve the API + built UI on localhost."""

from __future__ import annotations

import argparse
import os
import sys
import threading
import webbrowser
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="threatdesk", description="Run ThreatDesk on localhost.")
    ap.add_argument("--port", type=int, default=int(os.environ.get("THREATDESK_PORT", "8444") or 8444))
    ap.add_argument("--open", action="store_true", help="open the UI in the default browser")
    ap.add_argument("--reload", action="store_true", help="auto-reload on code changes (dev)")
    args = ap.parse_args(argv)

    os.environ["THREATDESK_PORT"] = str(args.port)
    # Agents (claude subprocesses) run with the repo as cwd; keep imports and
    # relative config paths anchored there however the script was launched.
    os.chdir(REPO_ROOT)
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    import uvicorn

    url = f"http://127.0.0.1:{args.port}/"
    print(f"ThreatDesk on {url}  (Ctrl+C to stop)")
    if args.open:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    uvicorn.run("api.main:app", host="127.0.0.1", port=args.port, reload=args.reload, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
