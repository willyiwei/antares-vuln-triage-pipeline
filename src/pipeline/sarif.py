"""SARIF report generation — industry-standard vulnerability reporting format."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import ScanResult, VulnerabilityFinding, Severity, FindingStatus


SEVERITY_MAP: dict[str, str] = {
    Severity.CRITICAL.value: "critical",
    Severity.HIGH.value: "high",
    Severity.MEDIUM.value: "medium",
    Severity.LOW.value: "low",
    Severity.INFO.value: "note",
}

STATUS_MAP: dict[str, str] = {
    FindingStatus.OPEN.value: "open",
    FindingStatus.TRIAGED.value: "reviewed",
    FindingStatus.IN_PROGRESS.value: "inProgress",
    FindingStatus.RESOLVED.value: "closed",
    FindingStatus.SUPPRESSED.value: "suppressed",
    FindingStatus.FALSE_POSITIVE.value: "falsePositive",
}


def build_sarif(scan_result: ScanResult) -> dict[str, Any]:
    """Convert a ScanResult into a SARIF 2.1.0 compliant dict."""
    now = datetime.now(timezone.utc).isoformat()

    runs: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []

    for finding in scan_result.findings:
        result: dict[str, Any] = {
            "ruleId": finding.rule_id or finding.id,
            "message": {"text": finding.title},
            "level": SEVERITY_MAP.get(finding.severity.value, "warning"),
            "locations": [],
            "suppressions": [],
            "metadata": {
                "confidence": finding.confidence,
                "governanceDecision": finding.governance_decision.value if finding.governance_decision else "none",
                "triageReasoning": finding.triage_reasoning,
            },
        }

        if finding.cve_id:
            result["cweId"] = finding.cwe_id or ""
            result["properties"] = {"cveId": finding.cve_id}

        if finding.cvss_score is not None:
            result["properties"] = result.get("properties", {})
            result["properties"]["cvssScore"] = finding.cvss_score

        if finding.file_path:
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                },
            }
            if finding.line_number:
                location["physicalLocation"]["region"] = {"startLine": finding.line_number}
            result["locations"].append(location)

        if finding.status == FindingStatus.SUPPRESSED:
            result["suppressions"].append({"kind": "inSource"})

        if finding.remediation:
            result["relatedLocations"] = [
                {
                    "message": {"text": finding.remediation},
                    "uri": finding.file_path or "",
                }
            ]

        results.append(result)

    run: dict[str, Any] = {
        "tool": {
            "driver": {
                "name": "Cisco AnTAres Vulnerability Triage Pipeline",
                "version": "0.1.0",
                "informationUri": "https://github.com/willyiwei/antares-vuln-triage-pipeline",
                "rules": [
                    {
                        "id": f.id,
                        "shortDescription": {"text": f.title},
                        "fullDescription": {"text": f.description},
                        "defaultConfiguration": {"level": SEVERITY_MAP.get(f.severity.value, "warning")},
                        "properties": {
                            "cweId": f.cwe_id or "",
                            "cvssScore": f.cvss_score,
                            "confidence": f.confidence,
                        },
                    }
                    for f in scan_result.findings
                ],
            }
        },
        "results": results,
        "columnKind": "utf16CodeUnits",
        "originalUriBaseIds": {},
    }

    runs.append(run)

    sarif_doc: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0",
        "version": "2.1.0",
        "serializationDate": now,
        "runs": runs,
    }

    return sarif_doc


def write_sarif(scan_result: ScanResult, output_path: Path | str) -> Path:
    """Write a ScanResult as a .sarif file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    sarif = build_sarif(scan_result)
    with open(path, "w") as f:
        json.dump(sarif, f, indent=2, default=str)

    return path


def write_json(scan_result: ScanResult, output_path: Path | str) -> Path:
    """Write a ScanResult as a human-readable JSON report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = scan_result.model_dump(mode="json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    return path
