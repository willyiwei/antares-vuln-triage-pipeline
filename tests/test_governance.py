"""Tests for the governance policy engine."""

import pytest
from .conftest import make_finding
from src.pipeline.governance import GovernancePolicy
from src.pipeline.models import GovernanceDecision, FindingStatus, Severity


def test_auto_accept_low_severity_high_confidence():
    policy = GovernancePolicy()
    f = make_finding(severity="low", confidence=0.90, cvss_score=3.5)
    decision, reason = policy.decide(f)
    assert decision == GovernanceDecision.AUTO_ACCEPT
    assert "auto-accept" in reason.lower() or "high confidence" in reason.lower()


def test_auto_reject_info_severity():
    policy = GovernancePolicy()
    f = make_finding(severity="info", confidence=0.50)
    decision, reason = policy.decide(f)
    assert decision == GovernanceDecision.AUTO_REJECT


def test_escalation_keyword_triggers_escalate():
    policy = GovernancePolicy()
    f = make_finding(
        title="Remote Code Execution via Deserialization",
        severity="critical",
        confidence=0.95,
        cvss_score=9.8,
    )
    decision, reason = policy.decide(f)
    assert decision == GovernanceDecision.ESCALATE
    assert "escalation keyword" in reason.lower()


def test_cve_requires_human_review():
    policy = GovernancePolicy(require_human_review_for_cve=True)
    f = make_finding(cve_id="CVE-2024-12345", severity="high", confidence=0.90)
    decision, reason = policy.decide(f)
    assert decision == GovernanceDecision.HUMAN_REVIEW
    assert "CVE" in reason


def test_cve_human_review_can_be_disabled():
    policy = GovernancePolicy(require_human_review_for_cve=False)
    f = make_finding(cve_id="CVE-2024-12345", severity="low", confidence=0.90)
    decision, reason = policy.decide(f)
    assert decision == GovernanceDecision.AUTO_ACCEPT


def test_batch_triage_counts():
    policy = GovernancePolicy()
    findings = [
        make_finding(severity="low", confidence=0.90),
        make_finding(severity="critical", confidence=0.95),
        make_finding(severity="info", confidence=0.80),
    ]
    results = policy.triage_batch(findings)
    decisions = [r["decision"] for r in results]
    assert "auto_accept" in decisions
    assert "auto_reject" not in decisions  # critical with high confidence goes to human review


def test_auto_reject_low_confidence():
    policy = GovernancePolicy()
    f = make_finding(severity="medium", confidence=0.10)
    decision, reason = policy.decide(f)
    assert decision == GovernanceDecision.AUTO_REJECT
