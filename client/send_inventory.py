"""
client/send_inventory.py
Description:
Collects client's installed package inventory and sends it to MiniSploit server.
Saves server findings in json file in client/scans/ and generates an HTML report
under client/reports/.

Run: python3 send_inventory.py
"""
import json
import subprocess
import requests
import sys
import socket
from datetime import datetime, timezone
from typing import List, Dict
from pathlib import Path

DEFAULT_IP = "127.0.0.1"

if len(sys.argv) > 1:
    server_ip = sys.argv[1]
else:
    server_ip = DEFAULT_IP

DEFAULT_SERVER_URL = f"http://{server_ip}:8000/scan"  # vm server IP
CLIENT_DIR = Path(__file__).resolve().parent
SCANS_DIR = CLIENT_DIR / "scans"
REPORTS_DIR = CLIENT_DIR / "reports"
POC_DIR = CLIENT_DIR / "poc"
IP_ADDRESS = socket.gethostbyname(socket.gethostname())
COMMANDS = ["id", "whoami", "hostname -I"]

def ensure_output_dirs():  # makes scans and reports directories
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def get_ubuntu_codename():  # gets machine ubuntu release name eg. 'focal'
    r = subprocess.run(["lsb_release", "-cs"], capture_output=True, text=True, check=True)
    return r.stdout.strip()


def get_hostname():  # gets hostname to use as client_id
    r = subprocess.run(["hostname"], capture_output=True, text=True, check=True)
    return r.stdout.strip()


def get_installed_packages():
    """
    Returns list of installed packages as list of dicts
    """
    r = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
        capture_output=True,
        text=True,
        check=True,
    )

    pkgs: List[Dict[str, str]] = []
    for line in r.stdout.splitlines():
        if "\t" not in line:
            continue
        name, version = line.split("\t", 1)
        pkgs.append({"name": name, "version": version})

    return pkgs


def post_inventory(server_url, payload, timeout=(5.0, 120.0)):
    """
    POST inventory to server. Includes 5s connect timeout and 120s read timeout
    """
    try:
        resp = requests.post(server_url, json=payload, timeout=timeout)
        resp.raise_for_status()
    except requests.exceptions.ConnectTimeout:
        raise SystemExit(f"ERROR: Timed out connecting to server at {server_url}")
    except requests.exceptions.ConnectionError as e:
        raise SystemExit(f"ERROR: Could not connect to server at {server_url} ({e})")
    except requests.exceptions.HTTPError as e:
        body = resp.text if "resp" in locals() else ""
        raise SystemExit(f"ERROR: Server returned HTTP error: {e}\nResponse body:\n{body}")

    try:
        return resp.json()
    except ValueError:
        raise SystemExit(f"ERROR: Server did not return JSON.\nResponse body:\n{resp.text}")


def save_scan(payload, findings, proofs=None):  # saves JSON scans
    out_file = SCANS_DIR / f"scan_{payload['client_id']}_{payload['ubuntu_release']}.json"

    with open(out_file, "w", encoding="utf-8") as fp:
        json.dump(
            {
                "request": payload,
                "findings": findings,
                "proofs": proofs or [],
            },
            fp,
            indent=2,
        )

    return out_file


def generate_report(scan_path):  # calls make_report.py
    make_report_path = CLIENT_DIR / "make_report.py"
    cmd = [sys.executable, str(make_report_path), str(scan_path)]
    subprocess.run(cmd, check=True)


def find_matching_pocs(findings):
    """
    Return a list of matching PoC files based on CVE IDs in findings.
    Matches filename like CVE-2025-32462.sh against finding['cve_id']
    """
    if not POC_DIR.exists():
        return []

    poc_files = [p for p in POC_DIR.iterdir() if p.is_file()]
    poc_by_cve = {p.stem.upper(): p for p in poc_files}

    matches = []
    seen = set()

    for finding in findings:
        cve_id = (finding.get("cve_id") or "").upper().strip()
        if not cve_id:
            continue

        poc_path = poc_by_cve.get(cve_id)
        if poc_path and cve_id not in seen:
            matches.append((finding, poc_path))
            seen.add(cve_id)

    return matches

def post_poc(action, ip):
    """
    POST poc request to server
    """
    url = f"http://{server_ip}:8000/run-poc"

    payload = {
        "action": action,
        "ip": ip
    }

    resp = requests.post(url, json=payload, timeout=(5.0, 120.0))
    resp.raise_for_status()
    return resp.json()

def run_poc_file(poc_path):
    """
    Execute a PoC based on file extension and return proof data.
    """
    print(f"\nRunning PoC: {poc_path.name}")

    if poc_path.suffix == ".py":
        result = post_poc("CVE-2026-24061", IP_ADDRESS)
        proof = {
            "script_name": poc_path.name,
            "commands": COMMANDS,
            "stdin": result.get("stdin",""),
            "stdout": result.get("stdout",""),
            "stderr": result.get("stderr",""),
        }

        return proof

    elif poc_path.suffix == ".sh":
        input_text = "\n".join(COMMANDS) + "\nexit\n"

        proc = subprocess.Popen(
            ["bash", str(poc_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        stdout, stderr = proc.communicate(input_text)

        proof = {
            "script_name": poc_path.name,
            "commands": COMMANDS,
            "stdin": input_text,
            "stdout": stdout,
            "stderr": stderr,
        }

        return proof

    else:
        print(f"Skipping unsupported PoC type: {poc_path.name}")
        return {
            "script_name": poc_path.name,
            "script_type": "unsupported",
            "commands": [],
            "stdin": "",
            "stdout": "",
            "stderr": f"Unsupported file type: {poc_path.suffix}",
            "exit_code": 1,
        }


def prompt_and_run_matching_pocs(findings):
    """
    Show any matching PoCs, prompt the user to run one, and return proofs.
    """
    matches = find_matching_pocs(findings)
    proofs = []

    if not matches:
        print("\nNo local PoC files matched the returned CVEs.")
        return proofs

    print("\nAvailable Proof of Concept Exploits:")
    for idx, (finding, poc_path) in enumerate(matches, start=1):
        print(
            f"  [{idx}] {poc_path.name} "
            f"(CVE: {finding['cve_id']}, package: {finding['package']}, priority: {finding.get('priority')})"
        )

    choice = input("\nTo run one of these PoC Exploits, enter the number of the PoC you'd like to run.\nIf you'd like to run multiple, enter the numbers separated by commas, or 'all' to run all matches.\nOtherwise, just press Enter to skip: ").strip().lower()
    if choice == "all":
        selection = list(range(1, len(matches) + 1))
    else:
        selection = []
        for s in choice.split(","):
            s = s.strip()
            if not s:
                continue
            if not s.isdigit():
                print(f"Skipping PoC execution.")
                continue

            idx = int(s)
            if 1 <= idx <= len(matches):
                if idx not in selection:
                    selection.append(idx)
            else:
                print(f"Selection out of range: {idx}")
                return proofs

    if not selection:
        print(f"Skipping PoC execution.")
        return proofs

    for idx in selection:
        finding, poc_path = matches[idx - 1]

        try:
            proof = run_poc_file(poc_path)
        except Exception as e:
            proof = {
                "script_name": poc_path.name,
                "script_type": "error",
                "commands": [],
                "stdin": "",
                "stdout": "",
                "stderr": f"Execution failed: {e}",
                "exit_code": 1,
            }

        proof_record = {
            "cve_id": finding["cve_id"],
            "package": finding["package"],
            **proof,
        }

        proofs.append(proof_record)

    return proofs


def main():  # collect inventory, send to server, print summary, save json results
    ensure_output_dirs()

    payload = {
        "client_id": get_hostname(),
        "ubuntu_release": get_ubuntu_codename(),
        "packages": get_installed_packages(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    print(f"Sending inventory for {payload['client_id']} ({payload['ubuntu_release']})")
    print(f"Server: {DEFAULT_SERVER_URL}")
    print(f"Packages: {len(payload['packages'])}")

    findings = post_inventory(DEFAULT_SERVER_URL, payload)

    counts = {}
    for f in findings:
        pr = (f.get("priority") or "unknown").lower()
        counts[pr] = counts.get(pr, 0) + 1
    print("\nFindings by priority:", counts)

    print(f"\nFindings returned: {len(findings)}")
    for f in findings[:200]:
        print(
            f"- {f['cve_id']} | {f['package']} {f['installed_version']} < {f.get('fixed_version')} | {f.get('priority')}"
        )

    proofs = prompt_and_run_matching_pocs(findings)

    scan_path = save_scan(payload, findings, proofs)
    print(f"\nSaved scan to: {scan_path}")

    generate_report(scan_path)


if __name__ == "__main__":
    main()
