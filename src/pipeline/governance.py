"""Governance engine — applies policy rules to triage findings."""

from __future__ import annotations

from .models import (
    VulnerabilityFinding,
    GovernanceDecision,
    FindingStatus,
    Severity,
)


class GovernancePolicy:
    """Policy engine that maps findings to governance decisions."""

    def __init__(
        self,
        auto_accept_severities: list[str] | None = None,
        auto_reject_severities: list[str] | None = None,
        confidence_threshold_auto_accept: float = 0.85,
        confidence_threshold_auto_reject: float = 0.3,
        require_human_review_for_cve: bool = True,
        max_cvss_for_auto_accept: float = 5.0,
        escalation_keywords: list[str] | None = None,
    ) -> None:
        self.auto_accept_severities = auto_accept_severities or ["low", "info"]
        self.auto_reject_severities = auto_reject_severities or []
        self.confidence_threshold_auto_accept = confidence_threshold_auto_accept
        self.confidence_threshold_auto_reject = confidence_threshold_auto_reject
        self.require_human_review_for_cve = require_human_review_for_cve
        self.max_cvss_for_auto_accept = max_cvss_for_auto_accept
        self.escalation_keywords = escalation_keywords or [
            "remote code execution",
            "privilege escalation",
            "auth bypass",
            "sql injection",
            "xss",
            "csrf",
            "deserialization",
            "prototype pollution",
        ]

    def decide(self, finding: VulnerabilityFinding) -> tuple[GovernanceDecision, str]:
        """
        Apply governance policy to a single finding.

        Returns (decision, reasoning).
        """
        # Check for escalation keywords in title/description
        text = f"{finding.title} {finding.description}".lower()
        for kw in self.escalation_keywords:
            if kw in text:
                return (
                    GovernanceDecision.ESCALATE,
                    f"Escalation keyword '{kw}' matched in finding text",
                )

        # CVSS-based auto-reject for low severity
        if finding.severity.value in self.auto_reject_severities:
            return (
                GovernanceDecision.AUTO_REJECT,
                f"Severity '{finding.severity.value}' is in auto-reject list",
            )

        # CVSS-based auto-accept for low severity and low confidence
        if (
            finding.severity.value in self.auto_accept_severities
            and finding.confidence >= self.confidence_threshold_auto_accept
            and (finding.cvss_score is None or finding.cvss_score <= self.max_cvss_for_auto_accept)
        ):
            return (
                GovernanceDecision.AUTO_ACCEPT,
                f"Low severity + high confidence ({finding.confidence:.2f}) + CVSS <= {self.max_cvss_for_auto_accept}",
            )

        # CVE requires human review by default
        if finding.cve_id and self.require_human_review_for_cve:
            return (
                GovernanceDecision.HUMAN_REVIEW,
                f"CVE '{finding.cve_id}' requires human review per policy",
            )

        # High confidence + low severity = auto accept
        if finding.confidence >= self.confidence_threshold_auto_accept:
            return (
                GovernanceDecision.AUTO_ACCEPT,
                f"High confidence ({finding.confidence:.2f}) meets auto-accept threshold",
            )

        # Low confidence = auto reject
        if finding.confidence <= self.confidence_threshold_auto_reject:
            return (
                GovernanceDecision.AUTO_REJECT,
                f"Low confidence ({finding.confidence:.2f}) below auto-reject threshold",
            )

        # Default: human review
        return (
            GovernanceDecision.HUMAN_REVIEW,
            "Default: finding requires human triage review",
        )

    def triage_batch(self, findings: list[VulnerabilityFinding]) -> list[dict]:
        """Apply governance policy to a batch of findings."""
        results = []
        for f in findings:
            decision, reasoning = self.decide(f)
            f.governance_decision = decision
            f.triage_reasoning = reasoning
            if decision == GovernanceDecision.AUTO_ACCEPT:
                f.status = FindingStatus.TRIAGED
            elif decision == GovernanceDecision.AUTO_REJECT:
                f.status = FindingStatus.SUPPRESSED
            results.append(
                {
                    "finding_id": f.id,
                    "decision": decision.value,
                    "reasoning": reasoning,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                }
            )
        return results
