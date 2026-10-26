"""Shared test fixtures."""

import pytest
from src.pipeline.models import VulnerabilityFinding, Severity, FindingStatus


@pytest.fixture
def make_finding():
    """Factory for creating VulnerabilityFinding instances for tests."""
    def _factory(
        title: str = "Test Finding",
        severity: str = "medium",
        confidence: float = 0.5,
        cvss_score: float | None = None,
        cve_id: str | None = None,
        cwe_id: str | None = None,
        file_path: str | None = "src/test.py",
        line_number: int | None = 10,
        rule_id: str = "TEST-001",
    ) -> VulnerabilityFinding:
        return VulnerabilityFinding(
            id="test-finding-001",
            cve_id=cve_id,
            cwe_id=cwe_id,
            title=title,
            severity=Severity(severity),
            cvss_score=cvss_score,
            rule_id=rule_id,
            file_path=file_path,
            line_number=line_number,
            confidence=confidence,
        )
    return _factory
