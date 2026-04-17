"""
# server/match_packages.py
Description:
Takes ubuntu_release and inventory of installed packages from client
and matches against local cve db and returns sorted list of findings
that have fixes
"""
import re
import sqlite3
import subprocess
import logging
from dataclasses import dataclass
from typing import List, Optional

log = logging.getLogger("minisploit.matcher")

#used to filter out fixed version strings that are actually dates
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

BAD_FIXED = {
        "code-not-compiled",
        "not-affected",
        "ignored",
        "needed",
        "deferred",
        "unknown",
    }

PRIO_ORDER = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "negligible": 4,
        "unknown": 5,
    }


@dataclass
class Finding:
    cve_id: str
    package: str
    installed_version: str
    status: str
    fixed_version: Optional[str]
    priority: str

def deb_version_lt(installed, fixed):
    """
    Debian/Ubuntu version comparisons are weird (epochs, tildes, etc.)
    Best to compare with dpkg --compare-versions.
    """
    result = subprocess.run(
        ["dpkg", "--compare-versions", installed, "lt", fixed],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def possible_names(pkg_name):
    """
    Handles simple name mismatches
    """
    pkg_name = pkg_name.lower().strip()
    names = [pkg_name]

    if pkg_name == "inetutils-telnetd":
        names.append("inetutils")

    for suffix in ("-base", "-utils", "-common", "-daemon", "-client", "-server"):
        if pkg_name.endswith(suffix):
            names.append(pkg_name[: -len(suffix)])

    # de-dupe while keeping order
    out: List[str] = []
    seen = set()
    for n in names:
        if n and n not in seen:
            out.append(n)
            seen.add(n)
    return out


def is_real_fixed_version(fixed_version):
    """
    Returns True only if fixed_version looks like a real Debian/Ubuntu version.
    Filters out tracker metadata like dates and notes.
    """
    if not fixed_version:
        return False

    fv = fixed_version.strip().lower()

    if not any(ch.isdigit() for ch in fv):
        return False

    if fv in BAD_FIXED:
        return False

    # date placeholders like '2026-01-05'
    if DATE_RE.match(fv):
        return False

    # multi-word values are usually notes, not version strings
    if " " in fv:
        return False

    return True


def match_inventory(ubuntu_release, packages, db_path, limit_per_package = 200):
    """
    Match client package inventory to CVEs for specific Ubuntu release
    """
    ubuntu_release = ubuntu_release.lower().strip()

    if not db_path.exists():
        log.warning("DB does not exist: %s", db_path)
        return []

    # Open db in read only to prevent accidental db creation
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    cur = conn.cursor()

    findings: List[Finding] = []

    for pkg_name, installed_version in packages:
        pkg_name = pkg_name.lower().strip()

        rows = []
        matched_name = None

        for candidate_name in possible_names(pkg_name):
            cur.execute(
                """
                SELECT pf.cve_id, pf.status, pf.fixed_version, c.priority
                FROM package_fixes pf
                JOIN cves c ON c.cve_id = pf.cve_id
                WHERE pf.package = ? AND pf.ubuntu_release = ?
                LIMIT ?
                """,
                (candidate_name, ubuntu_release, limit_per_package),
            )
            rows = cur.fetchall()
            if rows:
                matched_name = candidate_name
                break

        if not rows:
            continue

        # filters out tracker entries that don't have fixed versions
        for cve_id, status, fixed_version, priority in rows:
            if not is_real_fixed_version(fixed_version):
                continue

            try:
                if deb_version_lt(installed_version, fixed_version):
                    findings.append(
                        Finding(
                            cve_id=cve_id,
                            package=matched_name or pkg_name,
                            installed_version=installed_version,
                            status=status,
                            fixed_version=fixed_version,
                            priority=priority or "unknown",
                        )
                    )
            except Exception as e:
                log.debug(
                    "compare failed pkg=%s installed=%s fixed=%s err=%r",
                    pkg_name,
                    installed_version,
                    fixed_version,
                    e,
                )
                continue

    conn.close()

    # Deduplicate repeated CVE rows
    unique = {}
    for f in findings:
        key = (f.cve_id, f.package, f.installed_version, f.fixed_version)
        unique[key] = f

    # Sort findings so higher priority vulnerabilies are at the top
    findings_sorted = sorted(
        unique.values(),
        key=lambda f: (PRIO_ORDER.get((f.priority or "unknown").lower(), 99), f.package, f.cve_id),
    )
    return findings_sorted
