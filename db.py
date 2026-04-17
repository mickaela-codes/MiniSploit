"""
# server/db.py
Description:
Initializes local SQLite cve database and imports info from ubuntu cve tracker.
Also reads and writes metadata for validation purposes
"""
import sqlite3
import re

# regex pattern to parse ubuntu cve tracker
PKG_LINE_RE = re.compile(
    r"^(?P<rel>[a-z0-9][a-z0-9/\-]*)_(?P<pkg>[a-z0-9][a-z0-9+.\-]+):\s*(?P<rest>.+)$",
    re.IGNORECASE,
)
# finds priority lines
PRIORITY_RE = re.compile(r"^Priority:\s*(?P<prio>.+)$", re.IGNORECASE)

def parse_status_and_fixed(rest):
    #parses out status and version
    rest = rest.strip()
    status = rest.split()[0].lower()
    fixed_version = None

    # gets rid of parentheses
    m = re.search(r"\(([^)]+)\)", rest)
    if m:
        fixed_version = m.group(1).strip()
    return status, fixed_version

def import_uct_tracker_dirs(tracker_dirs, db_path, releases):
    """
    Import Ubuntu CVE Tracker data into the local DB.

    - Scans multiple tracker dirs (e.g. active + retired)
    - Walks recursively (handles subdir layouts)
    - De-dupes by CVE ID
    """
    tracker_dirs = list(tracker_dirs)
    missing = [d for d in tracker_dirs if not d.exists()]
    if missing:
        raise FileNotFoundError(
            "Couldn't find CVE tracker directory(s): " + ", ".join(str(d) for d in missing)
        )

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    imported_cves = 0
    imported_rows = 0
    skipped_files = 0

    # De-dupe by CVE id; prefer first-seen (caller should pass [active, retired])
    cve_files = {}
    for root in tracker_dirs:
        for p in root.rglob("CVE-*"):
            if p.is_file() and p.name.startswith("CVE-"):
                cve_files.setdefault(p.name, p)

    for cve_id, cve_file in sorted(cve_files.items()):
        try:
            lines = cve_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            skipped_files += 1
            continue

        priority = "unknown"
        for line in lines:
            pm = PRIORITY_RE.match(line)
            if pm:
                priority = pm.group("prio").strip().lower()
                break

        cur.execute(
            "INSERT OR REPLACE INTO cves (cve_id, priority, description) VALUES (?, ?, ?)",
            (cve_id, priority, ""),
        )
        imported_cves += 1

        for line in lines:
            m = PKG_LINE_RE.match(line)
            if not m:
                continue

            pkg = m.group("pkg").lower()
            raw_rel = m.group("rel").lower()
            rel = raw_rel.split("/")[-1]

            if rel not in releases:
                continue

            status, fixed_version = parse_status_and_fixed(m.group("rest"))
            cur.execute(
                """
                INSERT OR REPLACE INTO package_fixes
                (cve_id, package, ubuntu_release, status, fixed_version)
                VALUES (?, ?, ?, ?, ?)
                """,
                (cve_id, pkg, rel, status, fixed_version),
            )
            imported_rows += 1

    conn.commit()
    conn.close()

    return {
        "imported_cves": imported_cves,
        "imported_rows": imported_rows,
        "skipped_files": skipped_files,
    }
"""
def import_uct_active(active_dir, db_path, releases):
    #import ubuntu cve tracker data into local db

    if not active_dir.exists():
        raise FileNotFoundError(f"Couldn't find CVE tracker directory: {active_dir}")

    # open db
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    imported_cves = 0
    imported_rows = 0
    skipped_files = 0

    # loop through tracker files, skip anything not a CVE file
    for cve_file in sorted(active_dir.iterdir()):
        if not cve_file.name.startswith("CVE-"):
            continue

        cve_id = cve_file.name

        try:
            lines = cve_file.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            skipped_files += 1
            continue

        # get priority
        priority = "unknown"
        for line in lines:
            pm = PRIORITY_RE.match(line)
            if pm:
                priority = pm.group("prio").strip().lower()
                break

        # insert CVE row
        cur.execute(
            "INSERT OR REPLACE INTO cves (cve_id, priority, description) VALUES (?, ?, ?)",
            (cve_id, priority, ""),
        )
        imported_cves += 1

        #parse package lines and insert fix status, only for releases listed
        for line in lines:
            m = PKG_LINE_RE.match(line)
            if not m:
                continue

            pkg = m.group("pkg").lower()
            rel = m.group("rel").lower()
            if rel not in releases:
                continue

            status, fixed_version = parse_status_and_fixed(m.group("rest"))
            # insert into package_fixes
            cur.execute(
                '''
                INSERT OR REPLACE INTO package_fixes
                (cve_id, package, ubuntu_release, status, fixed_version)
                VALUES (?, ?, ?, ?, ?)
                ''',
                (cve_id, pkg, rel, status, fixed_version),
            )
            imported_rows += 1

    conn.commit()
    conn.close()

    return {
        "imported_cves": imported_cves,
        "imported_rows": imported_rows,
        "skipped_files": skipped_files,
    }
"""
def init_db(db_path):
    #ensures folder exists
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    #CVEs
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cves (
          cve_id TEXT PRIMARY KEY,
          priority TEXT,
          description TEXT
        )
        """
    )
    #package_fixes
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS package_fixes (
          cve_id TEXT,
          package TEXT,
          ubuntu_release TEXT,
          status TEXT,
          fixed_version TEXT,
          PRIMARY KEY (cve_id, package, ubuntu_release)
        )
        """
    )

    # metadata
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS meta (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        )
        """
    )
    #index speeds up matching lookups
    cur.execute("CREATE INDEX IF NOT EXISTS idx_pkg_rel ON package_fixes(package, ubuntu_release)")
    conn.commit()
    conn.close()

def clear_db(db_path):
    #wipe imported data but keep meta
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM package_fixes")
    cur.execute("DELETE FROM cves")
    # Keep meta
    conn.commit()
    conn.close()

def get_meta(db_path, key):
    #used by bootstrap.py to decide whether rebuild is needed
    if not db_path.exists():
        return None

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    try:
        cur.execute("SELECT value FROM meta WHERE key = ?", (key,))
        row = cur.fetchone()
        return row[0] if row else None
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def set_meta(db_path, key, value):
    #records metadata for later comparison
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value))
    conn.commit()
    conn.close()
