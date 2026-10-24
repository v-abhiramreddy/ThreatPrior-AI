"""Evidence-Based Risk Validation Service.

Evaluates normalized vulnerability evidence (CVSS, CISA KEV, EPSS, upstream telemetry statuses)
against a documented, transparent project policy ruleset (version 2026.1-policy).

CRITICAL POLICY PRINCIPLES:
1. Never overwrites the AI model's decision; presents an independent deterministic audit.
2. Identifies policy alignment or disagreement factually without claiming the model is "wrong"
   or that deterministic policy is an AI model.
3. Missing or failed EPSS data is never interpreted as zero risk.
4. Failed or timed-out CISA KEV queries are never treated as NOT_LISTED.
5. Evidence insufficiency is explicitly surfaced when upstream dependencies fail.
"""

from typing import List, Optional

from app.models.enums import SourceStatus
from app.models.schemas import VulnerabilityResponse
from app.models.triage import (
    RiskValidationResult,
    RiskValidationStatus,
    TriagePriority,
)

POLICY_RULES_VERSION = "2026.1-policy"

# Documented Project-Defined Policy Thresholds (Heuristic Baselines)
CVSS_CRITICAL_THRESHOLD = 9.0
CVSS_HIGH_THRESHOLD = 7.0
CVSS_MEDIUM_THRESHOLD = 4.0

EPSS_CRITICAL_HEURISTIC = 0.50  # 50% 30-day weaponization probability
EPSS_HIGH_HEURISTIC = 0.20      # 20% 30-day weaponization probability
EPSS_MEDIUM_HEURISTIC = 0.05    # 5% 30-day weaponization probability


class EvidenceRiskValidator:
    """Deterministic, transparent evidence validation engine for vulnerability triage."""

    def __init__(self, rules_version: str = POLICY_RULES_VERSION):
        self.rules_version = rules_version

    def validate(
        self,
        resp: VulnerabilityResponse,
        model_priority: TriagePriority,
    ) -> RiskValidationResult:
        norm = resp.normalized
        prov = resp.provenance

        # Extract telemetry facts
        cvss_score = norm.cvss_score if norm and norm.cvss_score is not None else None
        cvss_sev = norm.primary_severity.value if norm else "UNKNOWN"
        is_kev = prov.cisa_kev.is_listed
        kev_status = prov.cisa_kev.status
        epss_prob = prov.epss.probability if prov.epss.probability is not None else None
        epss_status = prov.epss.status

        findings: List[str] = []
        limitations: List[str] = []

        # -------------------------------------------------------------------
        # 1. Fact Collection & Upstream Health Auditing
        # -------------------------------------------------------------------
        # CVSS Evidence
        if prov.nvd.status in (SourceStatus.FAILED, SourceStatus.TIMEOUT, SourceStatus.RATE_LIMITED):
            findings.append(
                f"NIST NVD source is {prov.nvd.status.value}: {prov.nvd.error_message or 'Upstream query failure'}. CVSS score unavailable."
            )
            limitations.append("CVSS severity metrics unavailable due to NVD failure.")
        elif cvss_score is not None:
            findings.append(
                f"NVD CVSS Base Score: {cvss_score:.1f} ({cvss_sev}) "
                f"[Published: {prov.nvd.published_date or 'date unindexed'}]."
            )
        else:
            findings.append("NVD record indexed without published CVSS base score.")
            limitations.append("Unscored CVSS metric in NVD record.")

        # CISA KEV Evidence
        kev_failed = kev_status in (SourceStatus.FAILED, SourceStatus.TIMEOUT, SourceStatus.RATE_LIMITED)
        if kev_failed:
            findings.append(
                f"CISA KEV query status is {kev_status.value}: {prov.cisa_kev.error_message or 'Service unreachable'}. "
                "Warning: Query failure cannot be interpreted as NOT_LISTED."
            )
            limitations.append("CISA KEV catalog check failed; in-wild active exploitation status cannot be determined.")
        elif is_kev:
            kev_date = prov.cisa_kev.date_added or "recently"
            rw = f" · Ransomware: {prov.cisa_kev.known_ransomware_campaign_use}" if prov.cisa_kev.known_ransomware_campaign_use else ""
            findings.append(
                f"CISA KEV: Listed as confirmed active threat (Added: {kev_date}{rw}) "
                f"[Catalog Version: {prov.cisa_kev.catalog_version or '2026.10'}]."
            )
        else:
            findings.append(
                "CISA KEV: Not listed in catalog as of current sync. "
                "Notice: Absence from KEV catalog is not proof of safety."
            )

        # EPSS Evidence
        epss_failed = epss_status in (SourceStatus.FAILED, SourceStatus.TIMEOUT, SourceStatus.RATE_LIMITED)
        if epss_failed or epss_prob is None:
            findings.append(
                f"FIRST.org EPSS telemetry is {epss_status.value if epss_failed else 'missing'}: "
                "Policy rule enforces that missing or failed EPSS data is NOT interpreted as zero risk."
            )
            limitations.append("EPSS exploit prediction unavailable; probability cannot be factored.")
        else:
            pct_str = f", Top {(100 - prov.epss.percentile * 100):.1f}%" if prov.epss.percentile is not None else ""
            score_date = f" on {prov.epss.score_date}" if prov.epss.score_date else ""
            findings.append(
                f"FIRST.org EPSS: {epss_prob * 100:.2f}% 30-day exploit likelihood{pct_str} "
                f"(Observed{score_date} · Project heuristic threshold: >={EPSS_HIGH_HEURISTIC * 100:.0f}%)."
            )

        # -------------------------------------------------------------------
        # 2. Check for Insufficient Evidence
        # -------------------------------------------------------------------
        # Requirement: Do not treat a failed KEV lookup as NOT_LISTED.
        # If KEV lookup failed, or if NVD failed without CVSS and KEV is unlisted,
        # we cannot safely establish policy priority.
        if kev_failed or (cvss_score is None and is_kev is False):
            reason_parts = []
            if kev_failed:
                reason_parts.append(
                    f"CISA KEV catalog lookup {kev_status.value}. Per validation policy, failed lookups cannot be treated as NOT_LISTED."
                )
            if cvss_score is None:
                reason_parts.append("CVSS base score is unavailable from NVD.")

            return RiskValidationResult(
                model_priority=model_priority,
                evidence_priority=None,
                risk_validation_status=RiskValidationStatus.INSUFFICIENT_EVIDENCE,
                risk_factors=findings,
                validation_rules_version=self.rules_version,
                validation_explanation=(
                    f"Evidence-Based Validation Inconclusive: {' '.join(reason_parts)} "
                    "Available evidence is insufficient to evaluate against organizational risk policy rules."
                ),
            )

        # -------------------------------------------------------------------
        # 3. Deterministic Policy Rules Evaluation
        # -------------------------------------------------------------------
        effective_cvss = cvss_score or 0.0
        effective_epss = epss_prob if epss_prob is not None else 0.0

        responsible_rule: Optional[str] = None
        discrepancy_summary: Optional[str] = None

        # Policy Rule 1: CRITICAL
        # Confirmed KEV active threat + (Critical CVSS >= 8.5 or Extreme EPSS >= 0.50),
        # OR extreme remote CVSS >= 9.5
        if (is_kev and (effective_cvss >= 8.5 or effective_epss >= EPSS_CRITICAL_HEURISTIC)) or effective_cvss >= 9.5:
            evidence_priority = TriagePriority.CRITICAL
            responsible_rule = "Policy Rule 1 (Critical Severity)"
            policy_trigger = (
                "Confirmed CISA KEV active exploitation combined with critical impact (CVSS >= 8.5 or high EPSS)"
                if is_kev else "Extreme CVSS severity (>= 9.5) with unmitigated remote attack vector"
            )

        # Policy Rule 2: HIGH
        # Any confirmed KEV listing, OR elevated CVSS >= 7.0, OR high EPSS >= 0.20
        elif is_kev or effective_cvss >= CVSS_HIGH_THRESHOLD or effective_epss >= EPSS_HIGH_HEURISTIC:
            evidence_priority = TriagePriority.HIGH
            responsible_rule = "Policy Rule 2 (High Severity)"
            if is_kev:
                policy_trigger = "Confirmed CISA KEV listing without critical CVSS threshold"
            elif effective_cvss >= CVSS_HIGH_THRESHOLD:
                policy_trigger = f"Elevated CVSS severity ({effective_cvss:.1f} >= {CVSS_HIGH_THRESHOLD:.1f})"
            else:
                policy_trigger = f"High EPSS weaponization likelihood ({effective_epss * 100:.1f}% >= {EPSS_HIGH_HEURISTIC * 100:.0f}%)"

        # Policy Rule 3: MEDIUM
        # Moderate CVSS (4.0 <= cvss < 7.0) or moderate EPSS (>= 0.05) with NO KEV listing
        elif effective_cvss >= CVSS_MEDIUM_THRESHOLD or effective_epss >= EPSS_MEDIUM_HEURISTIC:
            evidence_priority = TriagePriority.MEDIUM
            responsible_rule = "Policy Rule 3 (Medium Severity)"
            policy_trigger = f"Moderate CVSS ({effective_cvss:.1f}) without confirmed in-the-wild exploitation"

        # Policy Rule 4: LOW
        # Low CVSS (< 4.0), low EPSS (< 0.05), and confirmed absence in CISA KEV
        else:
            evidence_priority = TriagePriority.LOW
            responsible_rule = "Policy Rule 4 (Low Severity)"
            policy_trigger = f"Low CVSS ({effective_cvss:.1f}) and no active threat indicators"

        # -------------------------------------------------------------------
        # 4. Alignment vs. Disagreement Assessment
        # -------------------------------------------------------------------
        if model_priority == evidence_priority:
            status = RiskValidationStatus.ALIGNED
            explanation = (
                f"Policy Aligned: Model-assigned '{model_priority.value}' priority is fully consistent with "
                f"deterministic evidence policy rules (v{self.rules_version}). Grounded trigger: {policy_trigger}."
            )
        else:
            status = RiskValidationStatus.DISAGREEMENT
            # Generate concise, exact explanation of the responsible rule and evidence
            if evidence_priority == TriagePriority.CRITICAL and model_priority == TriagePriority.HIGH:
                if not is_kev and effective_cvss >= 9.5:
                    discrepancy_summary = (
                        f"{responsible_rule} mandates Critical priority for extreme CVSS ({effective_cvss:.1f} >= 9.5) "
                        f"regardless of CISA KEV listing status. Responsible Evidence: NVD CVSS is {effective_cvss:.1f} (Critical) "
                        f"while CISA KEV status is NOT_LISTED, leading the AI model to recommend High whereas organizational policy enforces Critical."
                    )
                elif is_kev:
                    discrepancy_summary = (
                        f"{responsible_rule} mandates Critical priority for confirmed CISA KEV active exploitation. "
                        f"Responsible Evidence: Listed in CISA KEV with CVSS {effective_cvss:.1f} and EPSS {effective_epss * 100:.1f}%, "
                        f"whereas the AI model assigned High."
                    )
                else:
                    discrepancy_summary = (
                        f"{responsible_rule} mandates Critical priority ({policy_trigger}). "
                        f"Responsible Evidence: CVSS {effective_cvss:.1f}, EPSS {effective_epss * 100:.1f}%."
                    )
            elif evidence_priority and model_priority:
                discrepancy_summary = (
                    f"{responsible_rule} mandates {evidence_priority.value} priority ({policy_trigger}). "
                    f"Responsible Evidence: CVSS {effective_cvss:.1f}, CISA KEV {'Listed' if is_kev else 'Not Listed'}, "
                    f"EPSS {effective_epss * 100:.1f}%, whereas the AI model assigned {model_priority.value}."
                )

            discrepancy_clause = f" Responsible Policy Rule & Evidence: {discrepancy_summary}." if discrepancy_summary else ""

            explanation = (
                f"Policy Disagreement: Model assigned '{model_priority.value}', while deterministic evidence policy "
                f"evaluates to '{evidence_priority.value}'. Primary policy trigger: {policy_trigger}.{discrepancy_clause} "
                "Deterministic policy findings represent organizational rules, not an alternate AI model."
            )

        return RiskValidationResult(
            model_priority=model_priority,
            evidence_priority=evidence_priority,
            risk_validation_status=status,
            risk_factors=findings,
            validation_rules_version=self.rules_version,
            validation_explanation=explanation,
            policy_rule=responsible_rule,
            discrepancy_summary=discrepancy_summary,
        )


# Global instance
risk_validator = EvidenceRiskValidator()
