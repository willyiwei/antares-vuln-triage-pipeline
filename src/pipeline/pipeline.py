"""Main pipeline orchestrator — scan → triage → report."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path

from .config import PipelineConfig
from .models import ScanResult, VulnerabilityFinding, Severity, FindingStatus
from .antares_client import AnTAresClient, AnTAresClientError
from .governance import GovernancePolicy
from .sarif import write_sarif, write_json


class TriagePipeline:
    """Orchestrates the full vulnerability triage workflow."""

    def __init__(self, config: PipelineConfig | None = None) -> None:
        self.config = config or PipelineConfig()
        self.policy = GovernancePolicy()

    async def run_scan(self, repo_url: str, branch: str | None = None) -> ScanResult:
        """Run a full scan-triage-report cycle for a single repository."""
        scan_id = f"scan-{uuid.uuid4().hex[:12]}"
        scan = ScanResult(
            scan_id=scan_id,
            repo_url=repo_url,
            branch=branch,
        )

        try:
            async with AnTAresClient(self.config.antares) as client:
                # Submit scan
                job = await client.submit_scan(repo_url, branch=branch)
                scan_id = job.get("scan_id", scan_id)
                scan.scan_id = scan_id

                # Retrieve results
                raw_results = await client.get_scan_results(scan_id, wait=True)
                findings_raw = raw_results.get("findings", [])

                # Convert to VulnerabilityFinding objects
                scan.findings = [self._map_finding(f) for f in findings_raw]

        except AnTAresClientError as e:
            scan.error = str(e)
            # Fall back to mock data for demo/development
            scan.findings = self._generate_mock_findings(scan_id)

        # Run governance triage
        decisions = self.policy.triage_batch(scan.findings)

        # Aggregate
        scan.total_findings = len(scan.findings)
        scan.findings_by_severity = self._count_by_field(scan.findings, "severity")
        scan.findings_by_status = self._count_by_field(scan.findings, "status")
        scan.governance_summary = {
            "auto_accepted": sum(1 for d in decisions if d["decision"] == "auto_accept"),
            "auto_rejected": sum(1 for d in decisions if d["decision"] == "auto_reject"),
            "human_review_required": sum(1 for d in decisions if d["decision"] == "human_review"),
            "escalated": sum(1 for d in decisions if d["decision"] == "escalate"),
        }
        scan.completed_at = datetime.now(timezone.utc)

        # Write reports
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        write_sarif(scan, output_dir / f"{scan_id}.sarif")
        write_json(scan, output_dir / f"{scan_id}.json")

        return scan

    def run_scan_sync(self, repo_url: str, branch: str | None = None) -> ScanResult:
        """Synchronous wrapper for run_scan."""
        return asyncio.run(self.run_scan(repo_url, branch=branch))

    def _map_finding(self, raw: dict) -> VulnerabilityFinding:
        """Map a raw AnTAres finding dict to a VulnerabilityFinding model."""
        severity_str = raw.get("severity", "medium").lower()
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.MEDIUM

        status_str = raw.get("status", "open").lower()
        try:
            status = FindingStatus(status_str)
        except ValueError:
            status = FindingStatus.OPEN

        return VulnerabilityFinding(
            id=raw.get("id", ""),
            cve_id=raw.get("cve_id"),
            cwe_id=raw.get("cwe_id"),
            title=raw.get("title", "Untitled finding"),
            description=raw.get("description", ""),
            severity=severity,
            cvss_score=raw.get("cvss_score"),
            tool=raw.get("tool", "antares"),
            rule_id=raw.get("rule_id", ""),
            file_path=raw.get("file_path"),
            line_number=raw.get("line_number"),
            code_snippet=raw.get("code_snippet"),
            remediation=raw.get("remediation", ""),
            references=raw.get("references", []),
            status=status,
            confidence=raw.get("confidence", 0.5),
        )

    def _generate_mock_findings(self, scan_id: str) -> list[VulnerabilityFinding]:
        """Generate mock findings for demo/development when AnTAres is unavailable."""
        mock_data = [
            {
                "id": f"{scan_id}-f1",
                "cve_id": "CVE-2024-12345",
                "cwe_id": "CWE-79",
                "title": "Reflected Cross-Site Scripting in User Profile Endpoint",
                "description": "The /api/user/profile endpoint reflects user input without sanitization, allowing injection of arbitrary JavaScript.",
                "severity": "high",
                "cvss_score": 7.1,
                "tool": "antares",
                "rule_id": "XSS-REFLECTED-001",
                "file_path": "src/api/user/profile.py",
                "line_number": 42,
                "confidence": 0.92,
                "remediation": "Apply output encoding and Content-Security-Policy headers.",
            },
            {
                "id": f"{scan_id}-f2",
                "cve_id": "CVE-2024-23456",
                "cwe_id": "CWE-89",
                "title": "SQL Injection in Search Query Parameter",
                "description": "The search endpoint constructs SQL queries via string concatenation with user-controlled input.",
                "severity": "critical",
                "cvss_score": 9.8,
                "tool": "antares",
                "rule_id": "SQLI-CONCAT-002",
                "file_path": "src/db/search.py",
                "line_number": 87,
                "confidence": 0.97,
                "remediation": "Use parameterized queries or an ORM with bound parameters.",
            },
            {
                "id": f"{scan_id}-f3",
                "cwe_id": "CWE-200",
                "title": "Information Disclosure via Error Response",
                "description": "Stack traces and internal error details are returned in HTTP 500 responses.",
                "severity": "medium",
                "cvss_score": 5.3,
                "tool": "antares",
                "rule_id": "INFO-ERR-003",
                "file_path": "src/middleware/error_handler.py",
                "line_number": 15,
                "confidence": 0.88,
                "remediation": "Return generic error messages in production; log details server-side.",
            },
            {
                "id": f"{scan_id}-f4",
                "cwe_id": "CWE-611",
                "title": "XXE Vulnerability in XML Parser",
                "description": "The XML parser processes external entity declarations, enabling server-side request forgery.",
                "severity": "high",
                "cvss_score": 7.5,
                "tool": "antares",
                "rule_id": "XXE-PARSE-004",
                "file_path": "src/integrations/xml_processor.py",
                "line_number": 33,
                "confidence": 0.81,
                "remediation": "Disable external entity processing in the XML parser configuration.",
            },
            {
                "id": f"{scan_id}-f5",
                "cwe_id": "CWE-287",
                "title": "Improper Authentication on Admin API Endpoint",
                "description": "The /api/admin/health endpoint does not require authentication, exposing internal health data.",
                "severity": "medium",
                "cvss_score": 5.3,
                "tool": "antares",
                "rule_id": "AUTH-MISSING-005",
                "file_path": "src/routes/admin.py",
                "line_number": 7,
                "confidence": 0.95,
                "remediation": "Add authentication middleware to all admin routes.",
            },
        ]
        return [VulnerabilityFinding(**item) for item in mock_data]

    @staticmethod
    def _count_by_field(items: list[VulnerabilityFinding], field: str) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in items:
            val = getattr(item, field, "unknown")
            key = val.value if hasattr(val, "value") else str(val)
            counts[key] = counts.get(key, 0) + 1
        return counts
