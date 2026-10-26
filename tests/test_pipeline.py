"""Tests for the main pipeline orchestrator."""

import pytest
from src.pipeline.pipeline import TriagePipeline
from src.pipeline.config import PipelineConfig
from src.pipeline.models import ScanResult, VulnerabilityFinding, Severity


@pytest.fixture
def pipeline():
    return TriagePipeline(PipelineConfig())


def test_pipeline_generates_mock_findings_when_no_api(pipeline):
    """When AnTAres API is unreachable, pipeline falls back to mock data."""
    findings = pipeline._generate_mock_findings("test-scan-001")
    assert len(findings) == 5
    assert any(f.cve_id == "CVE-2024-12345" for f in findings)
    assert any(f.cve_id == "CVE-2024-23456" for f in findings)


def test_pipeline_counts_by_severity(pipeline):
    findings = pipeline._generate_mock_findings("test-scan-001")
    counts = pipeline._count_by_field(findings, "severity")
    assert "critical" in counts
    assert "high" in counts
    assert "medium" in counts


def test_pipeline_counts_by_status(pipeline):
    findings = pipeline._generate_mock_findings("test-scan-001")
    counts = pipeline._count_by_field(findings, "status")
    assert "open" in counts


def test_map_finding_creates_model(pipeline):
    raw = {
        "id": "f-001",
        "cve_id": "CVE-2024-0001",
        "cwe_id": "CWE-79",
        "title": "Test XSS",
        "description": "XSS in search",
        "severity": "high",
        "cvss_score": 7.1,
        "tool": "antares",
        "rule_id": "XSS-001",
        "file_path": "src/search.py",
        "line_number": 25,
        "confidence": 0.92,
    }
    f = pipeline._map_finding(raw)
    assert f.id == "f-001"
    assert f.cve_id == "CVE-2024-0001"
    assert f.severity == Severity.HIGH
    assert f.confidence == 0.92
    assert f.file_path == "src/search.py"


def test_map_finding_defaults(pipeline):
    raw = {"id": "f-002", "title": "Minimal finding"}
    f = pipeline._map_finding(raw)
    assert f.id == "f-002"
    assert f.severity == Severity.MEDIUM
    assert f.confidence == 0.5
