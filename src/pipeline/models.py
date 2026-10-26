"""Data models for vulnerability triage pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    FALSE_POSITIVE = "false_positive"


class GovernanceDecision(str, Enum):
    AUTO_ACCEPT = "auto_accept"
    AUTO_REJECT = "auto_reject"
    HUMAN_REVIEW = "human_review"
    ESCALATE = "escalate"


class VulnerabilityFinding(BaseModel):
    """A single vulnerability finding from AnTAres or a SARIF source."""

    id: str = Field(..., description="Unique finding identifier")
    cve_id: str | None = None
    cwe_id: str | None = None
    title: str = Field(..., max_length=500)
    description: str = ""
    severity: Severity = Severity.MEDIUM
    cvss_score: float | None = Field(None, ge=0.0, le=10.0)
    tool: str = "antares"  # source tool
    rule_id: str = ""
    file_path: str | None = None
    line_number: int | None = None
    code_snippet: str | None = None
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    status: FindingStatus = FindingStatus.OPEN
    governance_decision: GovernanceDecision | None = None
    confidence: float = Field(0.5, ge=0.0, le=1.0, description="AI confidence score")
    triage_reasoning: str = ""
    assigned_to: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self) -> None:
        if self.updated_at is None:
            self.updated_at = self.created_at


class ScanResult(BaseModel):
    """Aggregate result of a single scan operation."""

    scan_id: str
    repo_url: str | None = None
    commit_sha: str | None = None
    branch: str | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime | None = None
    total_findings: int = 0
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_status: dict[str, int] = Field(default_factory=dict)
    findings: list[VulnerabilityFinding] = Field(default_factory=list)
    governance_summary: dict = Field(default_factory=dict)
    error: str | None = None


class TriageResult(BaseModel):
    """Result of the governance triage step."""

    scan_id: str
    total_findings: int
    auto_accepted: int = 0
    auto_rejected: int = 0
    human_review_required: int = 0
    escalated: int = 0
    decisions: list[dict] = Field(default_factory=list)
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
