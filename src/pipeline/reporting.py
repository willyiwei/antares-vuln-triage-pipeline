"""Report generation — Markdown summary and HTML dashboard data."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .models import ScanResult, VulnerabilityFinding, Severity


def generate_summary_report(scan: ScanResult) -> str:
    """Generate a Markdown summary report for a scan."""
    lines = [
        f"# AnTAres Vulnerability Triage Report",
        f"",
        f"**Scan ID:** `{scan.scan_id}`",
        f"**Repository:** {scan.repo_url or 'local'}",
        f"**Branch:** {scan.branch or 'default'}",
        f"**Started:** {scan.started_at.isoformat()}",
        f"**Completed:** {scan.completed_at.isoformat() if scan.completed_at else 'in progress'}",
        f"",
        f"## Summary",
        f"",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total Findings | {scan.total_findings} |",
    ]

    for sev in ["critical", "high", "medium", "low", "info"]:
        count = scan.findings_by_severity.get(sev, 0)
        lines.append(f"| {sev.capitalize()} | {count} |")

    lines += [
        f"",
        f"## Governance Decisions",
        f"",
        f"| Decision | Count |",
        f"|----------|-------|",
    ]
    for decision, count in scan.governance_summary.items():
        lines.append(f"| {decision.replace('_', ' ').title()} | {count} |")

    lines += [
        f"",
        f"## Findings",
        f"",
    ]

    # Sort: critical first, then by confidence descending
    sorted_findings = sorted(
        scan.findings,
        key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity.value, 5), -f.confidence),
    )

    for f in sorted_findings:
        gov = f.governance_decision.value if f.governance_decision else "none"
        lines.append(f"### {f.title}")
        lines.append(f"")
        lines.append(f"- **ID:** `{f.id}`")
        if f.cve_id:
            lines.append(f"- **CVE:** `{f.cve_id}`")
        if f.cwe_id:
            lines.append(f"- **CWE:** `{f.cwe_id}`")
        lines.append(f"- **Severity:** {f.severity.value}")
        if f.cvss_score:
            lines.append(f"- **CVSS:** {f.cvss_score}")
        lines.append(f"- **Confidence:** {f.confidence:.0%}")
        lines.append(f"- **Governance:** {gov}")
        lines.append(f"- **File:** `{f.file_path or 'N/A'}`{f':{f.line_number}' if f.line_number else ''}")
        if f.remediation:
            lines.append(f"- **Remediation:** {f.remediation}")
        lines.append(f"")

    return "\n".join(lines)


def generate_html_dashboard_data(scan: ScanResult) -> dict:
    """Generate data structure for the web dashboard."""
    return {
        "scanId": scan.scan_id,
        "repoUrl": scan.repo_url,
        "branch": scan.branch,
        "startedAt": scan.started_at.isoformat(),
        "completedAt": scan.completed_at.isoformat() if scan.completed_at else None,
        "totalFindings": scan.total_findings,
        "bySeverity": scan.findings_by_severity,
        "byStatus": scan.findings_by_status,
        "governanceSummary": scan.governance_summary,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value,
                "cvssScore": f.cvss_score,
                "confidence": f.confidence,
                "governanceDecision": f.governance_decision.value if f.governance_decision else "none",
                "filePath": f.file_path,
                "lineNumber": f.line_number,
                "status": f.status.value,
                "remediation": f.remediation,
            }
            for f in scan.findings
        ],
    }
