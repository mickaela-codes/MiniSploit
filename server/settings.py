# server/settings.py
from pathlib import Path

BASE_DIR = Path.home() / "minisploit"

DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"

DB_PATH = DATA_DIR / "cve.db"

IMPORTER_VERSION = "6"  # bump if importer logic/schema changes


UCT_DIR = DATA_DIR / "ubuntu-cve-tracker"
UCT_ACTIVE_DIR = UCT_DIR / "active"
UCT_RETIRED_DIR = UCT_DIR / "retired"
UCT_URL = "https://git.launchpad.net/ubuntu-cve-tracker"

# Comma-separated releases. "focal" only, or "focal,jammy" etc.
DEFAULT_RELEASES = "noble,focal,jammy"
