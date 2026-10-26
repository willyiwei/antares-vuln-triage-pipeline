"""Tests for SARIF report generation."""

import json
from pathlib import Path
import pytest

from src.pipeline.models import ScanResult, VulnerabilityFinding, Severity, FindingStatus
from src.pipeline.sarif import build_sarif, write_sarif, write_json


@pytest.fixture
def sample_scan():
    return ScanResult(
        scan_id="test-sarif-001",
        repo_url="https://github.com/example/repo",
        branch="main",
        total_findings=2,
        findings=[
            VulnerabilityFinding(
                id="f-001",
                cve_id="CVE-2024-11111",
                cwe_id="CWE-79",
                title="Reflected XSS",
                severity=Severity.HIGH,
                cvss_score=7.1,
                file_path="src/app.py",
                line_number=42,
                confidence=0.92,
                remediation="Encode output",
            ),
            VulnerabilityFinding(
                id="f-002",
                cwe_id="CWE-89",
                title="SQL Injection",
                severity=Severity.CRITICAL,
                cvss_score=9.8,
                file_path="src/db.py",
                line_number=87,
                confidence=0.97,
                remediation="Use parameterized queries",
            ),
        ],
    )


def test_build_sarif_is_valid(sample_scan):
    sarif = build_sarif(sample_scan)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) == 2


def test_build_sarif_severity_mapping(sample_scan):
    sarif = build_sarif(sample_scan)
    results = sarif["runs"][0]["results"]
    levels = {r["level"] for r in results}
    assert "high" in levels
    assert "critical" in levels


def test_write_sarif_creates_file(tmp_path, sample_scan):
    out = tmp_path / "report.sarif"
    path = write_sarif(sample_scan, out)
    assert path.exists()
    with open(path) as f:
        data = json.load(f)
    assert data["version"] == "2.1.0"


def test_write_json_creates_file(tmp_path, sample_scan):
    out = tmp_path / "report.json"
    path = write_json(sample_scan, out)
    assert path.exists()
    with open(path) as f:
        data = json.load(f)
    assert data["scan_id"] == "test-sarif-001"
    assert data["total_findings"] == 2
