"""
server/bootstrap.py

Description: Ensures the ubuntu-cve-tracker repo exists locally and is up to date,
and rebuilds local db when necessary.
"""
import subprocess
import time

from datetime import datetime, timezone

from .db import clear_db, get_meta, init_db, set_meta, import_uct_tracker_dirs
from .settings import DB_PATH, UCT_ACTIVE_DIR, UCT_DIR, UCT_RETIRED_DIR, DEFAULT_RELEASES, UCT_URL, IMPORTER_VERSION

def git_head(repo_dir):
    # Used to check if repo was updated
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            text=True,
        ).strip()
    except Exception:
        return None

def ensure_repo(repo_dir):
    #ensures repo directory exists
    repo_dir.parent.mkdir(parents=True, exist_ok=True)
    if (repo_dir / ".git").exists():
        return
    #if repo doesn't exist, clone it
    subprocess.run(
        ["git", "clone", "--depth", "1", UCT_URL, str(repo_dir)],
        check=True,
        text=True,
        capture_output=True,
    )

def current_branch(repo_dir):
    #ensures correct repo branch
    branch = subprocess.check_output(
        ["git", "-C", str(repo_dir), "rev-parse", "--abbrev-ref", "HEAD"],
        text=True,
    ).strip()
    return "master" if branch == "HEAD" else branch

def run_git(cmd):
    #used to run git commands
    subprocess.run(cmd, check=True, text=True, capture_output=True)

def pull_repo(repo_dir, retries=6, base_delay_s=2):
    """
    Description:
      - Tries git fetch + reset
      - If it fails, waits longer each time (2s, 4s, 8s, 16s, ...)
      - Gives up after a few tries and raises a RuntimeError
        that includes the git stderr/stdout
    """
    branch = current_branch(repo_dir)
    last_err: subprocess.CalledProcessError | None = None

    for attempt in range(1, retries + 1):
        try:
            run_git(["git", "-C", str(repo_dir), "fetch", "--prune", "origin"])
            run_git(["git", "-C", str(repo_dir), "reset", "--hard", f"origin/{branch}"])
            return
        except subprocess.CalledProcessError as e:
            last_err = e

            # Extract stderr
            stderr = (e.stderr or "").lower()

            # Base backoff
            delay = base_delay_s * (2 ** (attempt - 1))

            # If Launchpad is throwing errors, be more patient
            if "503" in stderr or "rpc failed" in stderr or "http" in stderr:
                delay = max(delay, 10)

            # Cap so startup doesn't hang forever
            delay = min(delay, 30)

            time.sleep(delay)

    if last_err:
        raise RuntimeError(
            "git update failed after retries: "
            f"cmd={last_err.cmd} rc={last_err.returncode} "
            f"stdout={last_err.stdout.strip()} "
            f"stderr={last_err.stderr.strip()}"
        ) from last_err


def rebuild_cve_db(base_dir):
    """
    Update ubuntu-cve-tracker if possible, then rebuild DB only when needed.

    Rebuild triggers:
      - DB missing/unreadable
      - tracker commit differs from what's recorded in DB
      - releases set differs from what's recorded in DB
      - importer version changed
    """
    releases = {r.strip().lower() for r in DEFAULT_RELEASES.split(",")}
    releases_str = ",".join(sorted(releases))

    ensure_repo(UCT_DIR) #make sure repo exists

    head_before = git_head(UCT_DIR) # record initial head

    git_updated = False
    git_error = None

    try: #attempt update, if it fails it records the error
        pull_repo(UCT_DIR)
        git_updated = True
    except Exception as e:
        git_error = str(e)

    head_after = git_head(UCT_DIR) # gets head again and determines if its changed
    tracker_changed = bool(head_before and head_after and head_before != head_after)

    # checks if db is still valid
    db_releases = get_meta(DB_PATH, "releases")
    db_tracker_head = get_meta(DB_PATH, "tracker_head")
    db_importer_version = get_meta(DB_PATH, "importer_version")

    # Checks if anything is missing
    db_missing_or_unreadable = (
        (not DB_PATH.exists())
        or (db_releases is None or db_tracker_head is None or db_importer_version is None)
    )
    # decides if rebuild is needed
    needs_rebuild = (
        db_missing_or_unreadable
        or (db_releases != releases_str)
        or (head_after is not None and db_tracker_head != head_after)
        or (db_importer_version != IMPORTER_VERSION)
    )
    # logs stats
    stats = {
        "base_dir": str(base_dir),
        "db_path": str(DB_PATH),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "git_updated": git_updated,
        "git_error": git_error,
        "tracker_changed": tracker_changed,
        "tracker_head_before": head_before,
        "tracker_head_after": head_after,
        "releases": sorted(releases),
        "db_rebuilt": False,
        "needs_rebuild": bool(needs_rebuild),
        "db_releases": db_releases,
        "db_tracker_head": db_tracker_head,
        "importer_version": IMPORTER_VERSION,
        "db_importer_version": db_importer_version,
    }

    if not needs_rebuild:
        return stats

    # Rebuild DB
    init_db(DB_PATH)
    clear_db(DB_PATH)

    import_stats = import_uct_tracker_dirs([UCT_ACTIVE_DIR, UCT_RETIRED_DIR], DB_PATH, releases)

    # Records for future checks in order to skip rebuild safely
    set_meta(DB_PATH, "releases", releases_str)
    set_meta(DB_PATH, "tracker_head", head_after or "")
    set_meta(DB_PATH, "importer_version", IMPORTER_VERSION)

    stats.update(import_stats)
    stats["db_rebuilt"] = True
    return stats
