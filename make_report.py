import json
from pathlib import Path
from datetime import datetime
import sys
from typing import Optional

CLIENT_DIR = Path(__file__).resolve().parent
DEFAULT_SCANS_DIR = CLIENT_DIR / "scans"
DEFAULT_REPORTS_DIR = CLIENT_DIR / "reports"


def html_escape(s):
    return (str(s).replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#39;"))


def resolve_scan_path(arg: Optional[str]):
    if not arg:
        raise SystemExit("Usage: python3 make_report.py <scan_file>")
    path = Path(arg).expanduser().resolve()
    if not path.exists():
        raise SystemExit(f"Scan file not found: {path}")
    return path


def determine_risk_level(counts):
    if counts.get("critical", 0) > 0:
        return "Critical"
    if counts.get("high", 0) > 0:
        return "High"
    if counts.get("medium", 0) > 0:
        return "Medium"
    if counts.get("low", 0) > 0:
        return "Low"
    return "None"


def main():
    in_path = resolve_scan_path(sys.argv[1] if len(sys.argv) > 1 else None)
    DEFAULT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    data = json.loads(in_path.read_text(encoding="utf-8"))
    req = data["request"]
    findings = data["findings"]
    proofs = data.get("proofs", [])

    prio_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "negligible": 4, "unknown": 5}
    findings_sorted = sorted(
        findings,
        key=lambda f: (
            prio_order.get((f.get("priority") or "unknown").lower(), 99),
            f.get("package", "").lower(),
            f.get("cve_id", "")
        )
    )

    def fix_text(f):
        fv = f.get("fixed_version")
        if fv:
            return f"Upgrade <code>{html_escape(f['package'])}</code> to at least <code>{html_escape(fv)}</code>."
        return "Upgrade the affected package to a patched version."

    counts = {}
    for f in findings:
        pr = (f.get("priority") or "unknown").lower()
        counts[pr] = counts.get(pr, 0) + 1

    summary_order = ["critical", "high", "medium", "low", "negligible", "unknown"]
    summary_pills = []

    for level in summary_order:
        count = counts.get(level, 0)
        if count > 0:
            summary_pills.append(
                f'<span class="pill {level}">{level.title()}: {count}</span>'
            )

    summary_html = "".join(summary_pills)

    risk_level = determine_risk_level(counts)
    affected_packages = len({f["package"] for f in findings if f.get("package")})
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    rows = []
    for f in findings_sorted:
        priority = (f.get("priority") or "unknown").lower()
        priority_label = html_escape((f.get("priority") or "Unknown").title())
        cve_id = html_escape(f["cve_id"])
        rows.append(f"""
        <tr>
          <td>
            <span class="priority-pill priority-{priority}">
              {priority_label}
            </span>
          </td>
          <td>
            <a href="https://ubuntu.com/security/{cve_id}" target="_blank">
              <code>{cve_id}</code>
            </a>
          </td>
          <td><code>{html_escape(f["package"])}</code></td>
          <td><code>{html_escape(f["installed_version"])}</code></td>
          <td><code>{html_escape(f.get("fixed_version") or "-")}</code></td>
          <td>{fix_text(f)}</td>
        </tr>
        """)

    proofs_by_cve = {}
    for proof in proofs:
        cve_id = proof.get("cve_id", "UNKNOWN")
        proofs_by_cve.setdefault(cve_id, []).append(proof)

    def render_proof_sections():
        if not proofs:
            return "<p>No proof artifacts were attached to this scan.</p>"

        sections = []

        for f in findings_sorted:
            cve_id_raw = f["cve_id"]
            entries = proofs_by_cve.get(cve_id_raw, [])
            if not entries:
                continue

            cve_id = html_escape(cve_id_raw)
            blocks = []

            for p in entries:
                package = html_escape(p.get("package", ""))
                stdout = html_escape(p.get("stdout", "") or "(empty)")
                stderr = html_escape(p.get("stderr", "") or "(empty)")

                commands = p.get("commands", [])
                if commands:
                    commands_text = "\n".join(f"> {cmd}" for cmd in commands)
                else:
                    commands_text = "(none)"

                blocks.append(f"""
                <div class="proof-block">
                  <div><strong>CVE:</strong> <code>{cve_id}</code></div>
                  <div><strong>Package:</strong> <code>{package}</code></div>

                  <div class="proof-subtitle">Command Input</div>
                  <pre>{html_escape(commands_text)}</pre>

                  <div class="proof-subtitle">Command Output</div>
                  <pre>{stdout}</pre>

                  <div class="proof-subtitle">Exploit Execution Log</div>
                  <pre>{stderr}</pre>
                </div>
                """)

            sections.append("".join(blocks))

        if not sections:
            return "<p>Proof artifacts were attached, but none matched the listed CVEs.</p>"

        return "".join(sections)

    proof_html = render_proof_sections()
    risk_class = f"risk-{risk_level.lower()}"

    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>MiniSploit Report - {html_escape(req["client_id"])}</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      margin: 24px;
      color: #222;
      line-height: 1.5;
    }}

    h1 {{
      margin-bottom: 12px;
    }}

    h2 {{
      margin-top: 22px;
      margin-bottom: 12px;
    }}

    .risk-box {{
      margin-bottom: 16px;
      padding: 6px 10px;
      border-radius: 8px;
      font-weight: bold;
      display: inline-block;
      border: 1px solid #ccc;
      font-size: 14px;
    }}

    .risk-critical {{ background: #d9d9d9; color: #222; border-color: #bdbdbd; }}
    .risk-high {{ background: #f4b6b6; color: #6b1f1f; border-color: #e39c9c; }}
    .risk-medium {{ background: #f7c98b; color: #7a4b00; border-color: #e7b66f; }}
    .risk-low {{ background: #f3e39a; color: #6a5600; border-color: #e3d17d; }}
    .risk-none {{ background: #bfe3bf; color: #245c24; border-color: #a8d3a8; }}

    .meta {{
      color: #444;
      line-height: 1.8;
      margin-bottom: 16px;
    }}

    .clean-box {{
      margin-top: 20px;
      margin-bottom: 20px;
      padding: 14px;
      border-radius: 8px;
      background: #e6f9ec;
      border: 1px solid #8ed1a6;
      font-weight: bold;
      color: #2c7a4b;
    }}

    .summary-box {{
      margin-top: 6px;
      margin-bottom: 14px;
      color: #555;
    }}

    .summary-label {{
      margin-right: 8px;
      color: #444;
    }}

    .pill {{
      display: inline-block;
      margin-right: 6px;
      margin-top: 6px;
      padding: 3px 9px;
      border-radius: 999px;
      font-size: 13px;
      font-weight: bold;
    }}

    .pill.critical {{ background: #d9d9d9; color: #222; }}
    .pill.high {{ background: #f4b6b6; color: #6b1f1f; }}
    .pill.medium {{ background: #f7c98b; color: #7a4b00; }}
    .pill.low {{ background: #f3e39a; color: #6a5600; }}
    .pill.negligible {{ background: #bfe3bf; color: #245c24; }}
    .pill.unknown {{ background: #d9dde3; color: #4a5560; }}

    table {{
      border-collapse: collapse;
      width: 100%;
      margin-top: 12px;
    }}

    th, td {{
      border: 1px solid #e5e5e5;
      padding: 10px 8px;
      vertical-align: top;
      text-align: left;
    }}

    th {{
      background: #f4f4f4;
      font-weight: bold;
    }}

    .priority-pill {{
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 13px;
      font-weight: bold;
    }}

    .priority-critical {{ background: #d9d9d9; color: #222; }}
    .priority-high {{ background: #f4b6b6; color: #6b1f1f; }}
    .priority-medium {{ background: #f7c98b; color: #7a4b00; }}
    .priority-low {{ background: #f3e39a; color: #6a5600; }}
    .priority-negligible {{ background: #bfe3bf; color: #245c24; }}
    .priority-unknown {{ background: #d9dde3; color: #4a5560; }}

    .proof-block {{
      border: 1px solid #e5e5e5;
      border-radius: 8px;
      padding: 14px;
      margin-top: 12px;
      margin-bottom: 16px;
      background: #fafafa;
    }}

    .proof-subtitle {{
      margin-top: 12px;
      margin-bottom: 6px;
      font-weight: bold;
      color: #333;
    }}

    code {{
      background: #f7f7f7;
      padding: 2px 4px;
      border-radius: 4px;
      font-size: 0.95em;
    }}

    pre {{
      background: #f4f4f4;
      border: 1px solid #ddd;
      border-radius: 6px;
      padding: 10px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-wrap: break-word;
      margin: 0;
    }}

    a {{
      color: #0056b3;
      text-decoration: none;
    }}

    a:hover {{
      text-decoration: underline;
    }}

    .footer-note {{
      margin-top: 16px;
      color: #777;
      font-size: 0.9em;
    }}
  </style>
</head>
<body>
  <h1>MiniSploit Security Report</h1>

  <div class="risk-box {risk_class}">
    Risk Level: {risk_level}
  </div>

  <div class="meta">
    <div><b>Client:</b> <code>{html_escape(req["client_id"])}</code></div>
    <div><b>Ubuntu release:</b> <code>{html_escape(req["ubuntu_release"])}</code></div>
    <div><b>Packages scanned:</b> <code>{len(req["packages"])}</code></div>
    <div><b>Affected packages:</b> <code>{affected_packages}</code></div>
    <div><b>Vulnerabilities:</b> <code>{len(findings)}</code></div>
    <div><b>Generated:</b> <code>{generated}</code></div>
  </div>

  {"<div class='clean-box'>No known vulnerabilities were detected for this system based on current Ubuntu CVE data.</div>" if len(findings) == 0 else ""}

  <h2>Vulnerabilities</h2>

  <div class="summary-box">
    <b class="summary-label">Summary:</b>
    {summary_html}
  </div>

  <table>
    <thead>
      <tr>
        <th>Priority</th>
        <th>CVE</th>
        <th>Package</th>
        <th>Installed</th>
        <th>Fixed Version</th>
        <th>Recommended Fix</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows) if rows else "<tr><td colspan='6'>No vulnerabilities detected.</td></tr>"}
    </tbody>
  </table>

  {(
  "<h2>Proof of Vulnerability</h2>" + proof_html
  ) if proofs else ""}

  <p class="footer-note">
    Note: Findings are based on Ubuntu CVE tracking data and version comparisons (installed &lt; fixed).
  </p>

  <p class="footer-note">
    Source scan: <code>{html_escape(str(in_path))}</code>
  </p>
</body>
</html>
"""

    out_path = DEFAULT_REPORTS_DIR / f"report_{req['client_id']}_{req['ubuntu_release']}_{report_timestamp}.html"
    out_path.write_text(html, encoding="utf-8")
    print(f"Wrote report: {out_path}")


if __name__ == "__main__":
    main()
