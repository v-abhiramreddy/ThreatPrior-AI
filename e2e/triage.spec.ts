import { test, expect } from '@playwright/test';

test.describe('Phase 3 Correction: Genuine Strands Decider 2B + Amazon Bedrock AI Triage Tests', () => {
  test('should render genuine dual-model decision with Strands Decider 2B + Bedrock badge, distinct model provenance, and calibrated confidence', async ({
    page,
  }) => {
    // Mock successful dual-model decision endpoint
    await page.route('**/api/vulnerabilities/CVE-2021-44228/triage', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2021-44228',
          status: 'OK',
          retrieved_at: '2026-10-16T14:00:00.000Z',
          decision: {
            priority: 'Critical',
            rationale:
              'Active in-wild exploitation confirmed via CISA KEV catalog with maximum CVSS 10.0 severity and near-certain EPSS weaponization.',
            risk_factors: [
              'Active in-the-wild exploitation confirmed in CISA KEV catalog',
              'CVSS base metric rated CRITICAL (10.0)',
              'Elevated FIRST.org EPSS 30-day exploitation probability (99.8%)',
            ],
            recommended_action:
              'Immediately isolate vulnerable endpoints and apply emergency Log4j2 security updates.',
            confidence: 0.98,
            confidence_is_calibrated: false,
            recommendation_source: 'bedrock_synthesis',
            recommendation_is_verified: false,
            recommendation_url: null,
            confidence_explanation:
              'Model-derived Strands Decider 2B System-1 confidence: 98.0%. Rationale synthesized via Amazon Bedrock amazon.nova-lite-v1:0.',
            evidence_limitations: [
              'EPSS score is a 30-day empirical forecast as of 2026-10-15, not proof of weaponization.',
            ],
            engine: 'dual-ai',
            decider_model_id: 'strands-decider-2b',
            bedrock_model_id: 'amazon.nova-lite-v1:0',
            decider_status: 'success',
            bedrock_status: 'success',
            decided_at: '2026-10-16T14:00:01.000Z',
            fallback_reason: null,
          },
          normalized: {
            title: 'Apache Log4j2 Remote Code Execution Vulnerability',
            description:
              'Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration do not protect against LDAP endpoints.',
            primary_severity: 'CRITICAL',
            cvss_score: 10.0,
            cvss_version: '3.1',
            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            is_cisa_kev: true,
            cisa_required_action: 'Apply emergency updates per vendor instructions.',
            cisa_due_date: '2021-12-24',
            epss_probability: 0.998,
            epss_percentile: 1.0,
            affected_cpe_count: 365,
          },
          provenance: {
            nvd: {
              source: 'NIST National Vulnerability Database API v2.0',
              status: 'AVAILABLE',
              retrieved_at: '2026-10-16T14:00:00.000Z',
              vuln_status: 'Analyzed',
              published_date: '2021-12-10T10:15:08.767',
              last_modified_date: '2024-08-01T15:00:00.000',
              cvss_v31: {
                base_score: 10.0,
                severity: 'CRITICAL',
                vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
              },
              weaknesses: ['CWE-502'],
              cpe_configurations: ['cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'],
            },
            cisa_kev: {
              source: 'CISA Known Exploited Vulnerabilities Catalog',
              status: 'LISTED',
              retrieved_at: '2026-10-16T14:00:00.000Z',
              catalog_version: '2026.10.15',
              is_listed: true,
              date_added: '2021-12-10',
              vendor_project: 'Apache',
              product: 'Log4j2',
              due_date: '2021-12-24',
              required_action: 'Apply certified updates immediately.',
              known_ransomware_campaign_use: 'Known',
              notes: 'Confirmed listed in CISA Known Exploited Vulnerabilities catalog.',
            },
            epss: {
              source: 'FIRST.org EPSS API v3',
              status: 'AVAILABLE',
              retrieved_at: '2026-10-16T14:00:00.000Z',
              model_version: '1.0',
              probability: 0.998,
              percentile: 1.0,
              score_date: '2026-10-15',
              interpretive_note:
                'Estimated probability of active exploitation in next 30 days based on observed threat telemetry.',
            },
          },
          errors: [],
        }),
      });
    });

    await page.goto('/#analyze');

    // Search and analyze
    await page.locator('#cve-input').fill('CVE-2021-44228');
    await page.locator('#btn-analyze').click();

    // Verify AI Engine headers
    await expect(page.locator('#triage-title')).toContainText('Dual-Model AI Triage Decision');
    await expect(page.locator('#engine-badge')).toContainText('Strands Decider 2B + Bedrock');
    await expect(page.locator('#engine-subtitle')).toContainText('98.0%');
    await expect(page.locator('#engine-subtitle')).toContainText('strands-decider-2b');
    await expect(page.locator('#engine-subtitle')).toContainText('amazon.nova-lite-v1:0');

    // Verify Model Provenance Bar
    await expect(page.locator('#model-provenance-bar')).toBeVisible();
    await expect(page.locator('#provenance-decider-status')).toContainText('SUCCESS');
    await expect(page.locator('#provenance-bedrock-status')).toContainText('SUCCESS');
    await expect(page.locator('#provenance-calibration-status')).toContainText('Uncalibrated');

    // Verify Priority Banner & Rationale
    await expect(page.locator('#ai-priority-chip')).toContainText('Priority 1: Immediate Mitigation Required');
    await expect(page.locator('#ai-rationale-text')).toContainText('Active in-wild exploitation confirmed via CISA KEV');

    // Verify Risk Factors
    await expect(page.locator('#risk-factors-list')).toBeVisible();
    await expect(page.locator('#risk-factors-list')).toContainText('Active in-the-wild exploitation confirmed in CISA KEV catalog');
    await expect(page.locator('#risk-factors-list')).toContainText('CVSS base metric rated CRITICAL (10.0)');

    // Verify Confidence & Limitations
    await expect(page.locator('#confidence-explanation-text')).toContainText('Model-derived Strands Decider 2B System-1 confidence');
    await expect(page.locator('#evidence-limitations-list')).toContainText('EPSS score is a 30-day empirical forecast');

    // Verify Recommendation Provenance Disclosure
    await expect(page.locator('#remediation-provenance-disclosure')).toBeVisible();
    await expect(page.locator('#remediation-source-badge')).toContainText('Bedrock Synthesis (General Guidance)');

    // Verify Disclaimer
    await expect(page.locator('#state-loaded')).toContainText('AI DECISION SUPPORT NOTICE');
  });

  test('should render truthful decider-only degraded mode when Bedrock fails after Decider succeeds', async ({ page }) => {
    await page.route('**/api/vulnerabilities/CVE-2022-22965/triage', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2022-22965',
          status: 'OK',
          retrieved_at: '2026-10-16T14:10:00.000Z',
          decision: {
            priority: 'Critical',
            rationale:
              'Strands Decider 2B System-1 fast evaluation assigned Critical priority with calibrated confidence 95.0%. Stage 2 Amazon Bedrock rationale generation was unavailable (Bedrock rate limit exceeded).',
            risk_factors: [
              'Confirmed in-the-wild exploitation in CISA KEV (listed 2022-04-04).',
              'Elevated CVSS base score: 9.8.',
              'Strands Decider 2B System-1 flagged emergency operational mitigation requirement.',
            ],
            recommended_action: 'Apply emergency vendor patch or isolate Spring Framework endpoints.',
            recommendation_source: 'cisa_kev_directive',
            recommendation_is_verified: true,
            recommendation_url: 'https://www.cisa.gov/uscert/ed-22-02-spring4shell',
            confidence: 0.95,
            confidence_is_calibrated: false,
            confidence_explanation:
              'Model-derived Strands Decider 2B System-1 confidence score: 95.0%. Rationale synthesis degraded due to Bedrock failure.',
            evidence_limitations: [
              'Stage 2 Amazon Bedrock rationale synthesis was unavailable: Bedrock rate limit exceeded',
              'Decision rationale represents Strands Decider 2B System-1 fast evaluation only.',
            ],
            engine: 'decider-only',
            decider_model_id: 'strands-decider-2b',
            bedrock_model_id: null,
            decider_status: 'success',
            bedrock_status: 'failed',
            decided_at: '2026-10-16T14:10:01.000Z',
            fallback_reason: 'Bedrock Stage 2 unavailable: Bedrock rate limit exceeded',
          },
          normalized: {
            title: 'Spring Framework RCE (Spring4Shell)',
            description: 'Spring Framework RCE via data binding on JDK 9+.',
            primary_severity: 'CRITICAL',
            cvss_score: 9.8,
            cvss_version: '3.1',
            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            is_cisa_kev: true,
            cisa_required_action: 'Apply emergency updates immediately.',
            cisa_due_date: '2022-04-25',
            epss_probability: 0.97,
            epss_percentile: 0.99,
            affected_cpe_count: 5,
          },
          provenance: {
            nvd: {
              source: 'NIST NVD API v2.0',
              status: 'AVAILABLE',
              retrieved_at: '2026-10-16T14:10:00.000Z',
              cvss_v31: { base_score: 9.8, severity: 'CRITICAL', vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
              weaknesses: ['CWE-94'],
              cpe_configurations: ['cpe:2.3:a:vmware:spring_framework:*:*:*:*:*:*:*:*'],
            },
            cisa_kev: {
              source: 'CISA KEV',
              status: 'LISTED',
              is_listed: true,
              date_added: '2022-04-04',
              due_date: '2022-04-25',
              notes: 'Active exploitation in wild.',
            },
            epss: {
              source: 'FIRST.org EPSS',
              status: 'AVAILABLE',
              probability: 0.97,
              percentile: 0.99,
              interpretive_note: 'High exploitation probability.',
            },
          },
          errors: [],
        }),
      });
    });

    await page.goto('/#analyze');
    await page.locator('#cve-input').fill('CVE-2022-22965');
    await page.locator('#btn-analyze').click();

    await expect(page.locator('#triage-title')).toContainText('Strands Decider System-1 Decision');
    await expect(page.locator('#engine-badge')).toContainText('Strands Decider 2B (Decider-Only)');
    await expect(page.locator('#engine-subtitle')).toContainText('Bedrock unavailable');
    await expect(page.locator('#provenance-decider-status')).toContainText('SUCCESS');
    await expect(page.locator('#provenance-bedrock-status')).toContainText('FAILED');
    await expect(page.locator('#provenance-calibration-status')).toContainText('Uncalibrated');

    // Verify Authoritative CISA KEV Provenance Disclosure with URL
    await expect(page.locator('#remediation-provenance-disclosure')).toBeVisible();
    await expect(page.locator('#remediation-source-badge')).toContainText('CISA KEV Directive (Verified Source)');
    await expect(page.locator('#remediation-source-url')).toHaveAttribute('href', 'https://www.cisa.gov/uscert/ed-22-02-spring4shell');
  });

  test('should distinguish baseline decision when fallback heuristic is active', async ({ page }) => {
    // Mock baseline fallback response
    await page.route('**/api/vulnerabilities/CVE-2023-38606/triage', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2023-38606',
          status: 'OK',
          retrieved_at: '2026-10-16T14:05:00.000Z',
          decision: {
            priority: 'High',
            rationale:
              'No record in CISA KEV catalog (catalog absence is not proof of safety). CVSS base score rated at 7.8.',
            risk_factors: ['CVSS base metric rated HIGH (7.8).'],
            recommended_action:
              'Expedite patching within current maintenance window; verify perimeter ingress and egress monitoring.',
            confidence: 0.88,
            confidence_is_calibrated: false,
            confidence_explanation:
              'Standard baseline heuristic evaluation: elevated threat signals observed across CVSS/EPSS. (Uncalibrated heuristic score)',
            evidence_limitations: [
              'Not listed in CISA KEV catalog; absence indicates no confirmed BOD 22-01 campaign, not proof of safety.',
            ],
            engine: 'baseline',
            decider_model_id: null,
            bedrock_model_id: null,
            decider_status: 'unavailable',
            bedrock_status: 'not_invoked',
            model_id: 'baseline-heuristic-v1',
            decided_at: '2026-10-16T14:05:01.000Z',
            fallback_reason: 'Strands Decider 2B unavailable: Windows native PyTorch DLL execution is blocked by OS security policy (WinError 4551).',
          },
          normalized: {
            title: 'Apple Kernel Memory Map Privilege Escalation',
            description: 'Hardware MMIO page table register bypass allows privilege escalation.',
            primary_severity: 'HIGH',
            cvss_score: 7.8,
            cvss_version: '3.1',
            cvss_vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
            is_cisa_kev: false,
            cisa_required_action: null,
            cisa_due_date: null,
            epss_probability: 0.08,
            epss_percentile: 0.72,
            affected_cpe_count: 12,
          },
          provenance: {
            nvd: {
              source: 'NIST National Vulnerability Database API v2.0',
              status: 'AVAILABLE',
              retrieved_at: '2026-10-16T14:05:00.000Z',
              cvss_v31: {
                base_score: 7.8,
                severity: 'HIGH',
                vector_string: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
              },
              weaknesses: ['CWE-284'],
              cpe_configurations: ['cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*'],
            },
            cisa_kev: {
              source: 'CISA Known Exploited Vulnerabilities Catalog',
              status: 'NOT_LISTED',
              retrieved_at: '2026-10-16T14:05:00.000Z',
              is_listed: false,
              notes: 'Not cataloged in CISA KEV catalog (catalog absence is not proof of safety).',
            },
            epss: {
              source: 'FIRST.org EPSS API v3',
              status: 'AVAILABLE',
              retrieved_at: '2026-10-16T14:05:00.000Z',
              probability: 0.08,
              percentile: 0.72,
              interpretive_note: 'Estimated probability of active exploitation in next 30 days.',
            },
          },
          errors: [],
        }),
      });
    });

    await page.goto('/#analyze');

    await page.locator('#cve-input').fill('CVE-2023-38606');
    await page.locator('#btn-analyze').click();

    // Verify Baseline Engine indicators
    await expect(page.locator('#triage-title')).toContainText('Baseline Triage Decision');
    await expect(page.locator('#engine-badge')).toContainText('Baseline Heuristic (Rule Fallback)');
    await expect(page.locator('#engine-subtitle')).toContainText('AI fallback active');
    await expect(page.locator('#engine-subtitle')).toContainText('Uncalibrated heuristic score');
    await expect(page.locator('#provenance-decider-status')).toContainText('UNAVAILABLE');
    await expect(page.locator('#provenance-calibration-status')).toContainText('Uncalibrated');
    await expect(page.locator('#state-loaded')).toContainText('BASELINE DECISION NOTICE');
  });

  test('should display clear error state when AI triage is unavailable and fallback is disabled', async ({ page }) => {
    // Mock 503 error
    await page.route('**/api/vulnerabilities/CVE-2024-11111/triage', async (route) => {
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({
          detail: 'Strands Decider 2B evaluation failed and baseline fallback is disabled. Diagnostic: Strands Decider 2B unavailable',
          errors: ['Decider service unreachable'],
        }),
      });
    });

    await page.goto('/#analyze');

    await page.locator('#cve-input').fill('CVE-2024-11111');
    await page.locator('#btn-analyze').click();

    await expect(page.locator('#state-error')).toBeVisible();
    await expect(page.locator('#state-error')).toContainText('Strands Decider 2B evaluation failed and baseline fallback is disabled');
  });

  test('should render evidence-based risk policy validation with agreement and factual findings', async ({ page }) => {
    await page.route('**/api/vulnerabilities/CVE-2021-44228/triage', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2021-44228',
          status: 'OK',
          retrieved_at: '2026-10-16T14:00:00.000Z',
          decision: {
            priority: 'Critical',
            rationale: 'Active in-wild exploitation confirmed via CISA KEV catalog.',
            risk_factors: ['CISA KEV Listed', 'CVSS 10.0', 'EPSS 99%'],
            recommended_action: 'Apply emergency vendor update.',
            confidence: 0.98,
            confidence_is_calibrated: false,
            confidence_explanation: 'Model-derived Strands Decider 2B confidence score: 98.0%.',
            evidence_limitations: [],
            engine: 'decider-only',
            decider_model_id: 'strands-decider-2b',
            decider_status: 'success',
            bedrock_status: 'failed',
            decided_at: '2026-10-16T14:00:01.000Z',
            risk_validation: {
              model_priority: 'Critical',
              evidence_priority: 'Critical',
              risk_validation_status: 'aligned',
              risk_factors: [
                'NVD CVSS Base Score: 10.0 (CRITICAL) [Published: 2021-12-10T10:15:08.767].',
                'CISA KEV: Listed as confirmed active threat (Added: 2021-12-10 · Ransomware: Known) [Catalog Version: 2026.10.15].',
                'FIRST.org EPSS: 99.80% 30-day exploit likelihood, Top 0.2% (Observed on 2026-10-15 · Project heuristic threshold: >=20%).',
              ],
              validation_rules_version: '2026.1-policy',
              validation_explanation: "Policy Aligned: Model-assigned 'Critical' priority is fully consistent with deterministic evidence policy rules (v2026.1-policy).",
            },
          },
          risk_validation: {
            model_priority: 'Critical',
            evidence_priority: 'Critical',
            risk_validation_status: 'aligned',
            risk_factors: [
              'NVD CVSS Base Score: 10.0 (CRITICAL) [Published: 2021-12-10T10:15:08.767].',
              'CISA KEV: Listed as confirmed active threat (Added: 2021-12-10 · Ransomware: Known) [Catalog Version: 2026.10.15].',
              'FIRST.org EPSS: 99.80% 30-day exploit likelihood, Top 0.2% (Observed on 2026-10-15 · Project heuristic threshold: >=20%).',
            ],
            validation_rules_version: '2026.1-policy',
            validation_explanation: "Policy Aligned: Model-assigned 'Critical' priority is fully consistent with deterministic evidence policy rules (v2026.1-policy).",
          },
          normalized: {
            title: 'Apache Log4j2 Remote Code Execution Vulnerability',
            description: 'Apache Log4j2 JNDI RCE vulnerability.',
            primary_severity: 'CRITICAL',
            cvss_score: 10.0,
            is_cisa_kev: true,
            affected_cpe_count: 1,
          },
          provenance: {
            nvd: { source: 'NVD', status: 'AVAILABLE', weaknesses: ['CWE-502'], cpe_configurations: [] },
            cisa_kev: { source: 'CISA', status: 'LISTED', is_listed: true, notes: 'Listed' },
            epss: { source: 'EPSS', status: 'AVAILABLE', probability: 0.998, percentile: 1.0, interpretive_note: 'High' },
          },
          errors: [],
        }),
      });
    });

    await page.goto('/#analyze');
    await page.locator('#cve-input').fill('CVE-2021-44228');
    await page.locator('#btn-analyze').click();

    await expect(page.locator('#ai-priority-chip')).toContainText('Priority 1');
    await expect(page.locator('#evidence-priority-chip')).toContainText('Policy Assessment: Critical');
    await expect(page.locator('#risk-aligned-badge')).toContainText('Policy Aligned');

    // Risk validation panel checks
    await expect(page.locator('#risk-validation-panel')).toBeVisible();
    await expect(page.locator('#risk-validation-panel')).toContainText('Rules v2026.1-policy (Deterministic Findings)');
    await expect(page.locator('#validation-explanation-text')).toContainText('Policy Aligned');
    await expect(page.locator('#validation-findings-list')).toContainText('NVD CVSS Base Score: 10.0');
    await expect(page.locator('#validation-findings-list')).toContainText('CISA KEV: Listed as confirmed active threat');
  });

  test('should render clear disagreement indicator and explanation when model and policy differ', async ({ page }) => {
    await page.route('**/api/vulnerabilities/CVE-2021-44228/triage', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2021-44228',
          status: 'OK',
          retrieved_at: '2026-10-16T14:00:00.000Z',
          decision: {
            priority: 'High', // Model chose High
            rationale: 'Strands Decider 2B System-1 selected High priority based on criteria matching.',
            risk_factors: ['Severe RCE capability'],
            recommended_action: 'Patch within standard expedited SLA.',
            confidence: 0.58,
            confidence_is_calibrated: false,
            confidence_explanation: 'Model-derived Strands Decider 2B confidence score: 58.0%.',
            evidence_limitations: [],
            engine: 'decider-only',
            decider_model_id: 'strands-decider-2b',
            decider_status: 'success',
            bedrock_status: 'failed',
            decided_at: '2026-10-16T14:00:01.000Z',
            risk_validation: {
              model_priority: 'High',
              evidence_priority: 'Critical',
              risk_validation_status: 'disagreement',
              risk_factors: [
                'NVD CVSS Base Score: 10.0 (CRITICAL) [Published: 2021-12-10T10:15:08.767].',
                'CISA KEV: Listed as confirmed active threat (Added: 2021-12-10) [Catalog Version: 2026.10.15].',
              ],
              validation_rules_version: '2026.1-policy',
              validation_explanation: "Policy Disagreement: Model assigned 'High', while deterministic evidence policy evaluates to 'Critical'. Primary policy trigger: Confirmed CISA KEV active exploitation combined with critical impact. Deterministic policy findings represent organizational rules, not an alternate AI model.",
            },
          },
          risk_validation: {
            model_priority: 'High',
            evidence_priority: 'Critical',
            risk_validation_status: 'disagreement',
            risk_factors: [
              'NVD CVSS Base Score: 10.0 (CRITICAL) [Published: 2021-12-10T10:15:08.767].',
              'CISA KEV: Listed as confirmed active threat (Added: 2021-12-10) [Catalog Version: 2026.10.15].',
            ],
            validation_rules_version: '2026.1-policy',
            validation_explanation: "Policy Disagreement: Model assigned 'High', while deterministic evidence policy evaluates to 'Critical'. Primary policy trigger: Confirmed CISA KEV active exploitation combined with critical impact. Deterministic policy findings represent organizational rules, not an alternate AI model.",
          },
          normalized: {
            title: 'Apache Log4j2 RCE',
            description: 'Apache Log4j2 JNDI RCE.',
            primary_severity: 'CRITICAL',
            cvss_score: 10.0,
            is_cisa_kev: true,
            affected_cpe_count: 1,
          },
          provenance: {
            nvd: { source: 'NVD', status: 'AVAILABLE', weaknesses: ['CWE-502'], cpe_configurations: [] },
            cisa_kev: { source: 'CISA', status: 'LISTED', is_listed: true, notes: 'Listed' },
            epss: { source: 'EPSS', status: 'AVAILABLE', probability: 0.998, percentile: 1.0, interpretive_note: 'High' },
          },
          errors: [],
        }),
      });
    });

    await page.goto('/#analyze');
    await page.locator('#cve-input').fill('CVE-2021-44228');
    await page.locator('#btn-analyze').click();

    // Verify model priority is preserved as High (Priority 2)
    await expect(page.locator('#ai-priority-chip')).toContainText('Priority 2');
    // Policy assessment chip shows Critical
    await expect(page.locator('#evidence-priority-chip')).toContainText('Policy Assessment: Critical');
    // Disagreement badge is visible
    await expect(page.locator('#risk-disagreement-badge')).toBeVisible();
    await expect(page.locator('#risk-disagreement-badge')).toContainText('Policy Disagreement (Model: High · Policy: Critical)');

    // Disagreement alert in validation panel
    await expect(page.locator('#validation-disagreement-alert')).toBeVisible();
    await expect(page.locator('#validation-disagreement-alert')).toContainText('Model Decision vs. Deterministic Policy Discrepancy');
    await expect(page.locator('#validation-disagreement-alert')).toContainText('not a second AI model');
  });

  test('should render insufficient evidence badge when CISA KEV query fails', async ({ page }) => {
    await page.route('**/api/vulnerabilities/CVE-2024-55555/triage', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2024-55555',
          status: 'PARTIAL',
          retrieved_at: '2026-10-16T14:00:00.000Z',
          decision: {
            priority: 'Medium',
            rationale: 'Heuristic evaluation under degraded telemetry.',
            risk_factors: ['Moderate CVSS'],
            recommended_action: 'Investigate manually.',
            confidence: 0.50,
            confidence_is_calibrated: false,
            confidence_explanation: 'Telemetry degraded.',
            evidence_limitations: ['CISA KEV query failed.'],
            engine: 'baseline',
            decider_status: 'not_invoked',
            bedrock_status: 'not_invoked',
            decided_at: '2026-10-16T14:00:01.000Z',
            risk_validation: {
              model_priority: 'Medium',
              evidence_priority: null,
              risk_validation_status: 'insufficient_evidence',
              risk_factors: [
                'NVD CVSS Base Score: 5.5 (MEDIUM) [Published: 2024-01-01].',
                'CISA KEV query status is TIMEOUT: Service unreachable. Warning: Query failure cannot be interpreted as NOT_LISTED.',
              ],
              validation_rules_version: '2026.1-policy',
              validation_explanation: 'Evidence-Based Validation Inconclusive: CISA KEV catalog lookup TIMEOUT. Per validation policy, failed lookups cannot be treated as NOT_LISTED.',
            },
          },
          risk_validation: {
            model_priority: 'Medium',
            evidence_priority: null,
            risk_validation_status: 'insufficient_evidence',
            risk_factors: [
              'NVD CVSS Base Score: 5.5 (MEDIUM) [Published: 2024-01-01].',
              'CISA KEV query status is TIMEOUT: Service unreachable. Warning: Query failure cannot be interpreted as NOT_LISTED.',
            ],
            validation_rules_version: '2026.1-policy',
            validation_explanation: 'Evidence-Based Validation Inconclusive: CISA KEV catalog lookup TIMEOUT. Per validation policy, failed lookups cannot be treated as NOT_LISTED.',
          },
          normalized: {
            title: 'Sample Vulnerability',
            description: 'Sample description',
            primary_severity: 'MEDIUM',
            cvss_score: 5.5,
            is_cisa_kev: false,
            affected_cpe_count: 1,
          },
          provenance: {
            nvd: { source: 'NVD', status: 'AVAILABLE', weaknesses: [], cpe_configurations: [] },
            cisa_kev: { source: 'CISA', status: 'TIMEOUT', is_listed: false, notes: 'Timeout', error_message: 'Service unreachable' },
            epss: { source: 'EPSS', status: 'AVAILABLE', probability: 0.01, percentile: 0.1, interpretive_note: 'Low' },
          },
          errors: ['CISA KEV timeout'],
        }),
      });
    });

    await page.goto('/#analyze');
    await page.locator('#cve-input').fill('CVE-2024-55555');
    await page.locator('#btn-analyze').click();

    await expect(page.locator('#evidence-priority-chip')).toContainText('Policy Assessment: INSUFFICIENT EVIDENCE');
    await expect(page.locator('#risk-insufficient-badge')).toBeVisible();
    await expect(page.locator('#risk-insufficient-badge')).toContainText('Insufficient Telemetry for Policy');
    await expect(page.locator('#validation-explanation-text')).toContainText('cannot be treated as NOT_LISTED');
  });

  test('should display accurate fallback when dual-ai response has missing bedrock model ID', async ({ page }) => {
    await page.route('**/api/vulnerabilities/CVE-2023-4863/triage', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2023-4863',
          status: 'OK',
          retrieved_at: '2026-10-16T14:00:00.000Z',
          decision: {
            priority: 'Critical',
            rationale: 'Critical heap buffer overflow in libwebp.',
            risk_factors: ['CVSS 8.8'],
            recommended_action: 'Upgrade libwebp.',
            confidence: 0.95,
            confidence_is_calibrated: false,
            recommendation_source: 'bedrock_synthesis',
            recommendation_is_verified: false,
            confidence_explanation: 'Model-derived confidence.',
            evidence_limitations: [],
            engine: 'dual-ai',
            decider_model_id: 'strands-decider-2b',
            bedrock_model_id: null,
            decider_status: 'success',
            bedrock_status: 'unavailable',
            decided_at: '2026-10-16T14:00:01.000Z',
          },
          normalized: {
            title: 'Heap buffer overflow in libwebp',
            description: 'Heap buffer overflow in libwebp in Google Chrome.',
            primary_severity: 'CRITICAL',
            cvss_score: 8.8,
            cvss_version: '3.1',
            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
            is_cisa_kev: true,
            cisa_required_action: 'Apply updates.',
            cisa_due_date: '2023-10-04',
            epss_probability: 0.85,
            epss_percentile: 0.99,
            affected_cpe_count: 10,
          },
          provenance: {
            nvd: { source: 'NVD', status: 'AVAILABLE', weaknesses: [], cpe_configurations: [] },
            cisa_kev: { source: 'CISA KEV', status: 'LISTED', is_listed: true },
            epss: { source: 'EPSS', status: 'AVAILABLE', probability: 0.85 },
          },
        }),
      });
    });

    await page.goto('/#analyze');
    await page.locator('#cve-input').fill('CVE-2023-4863');
    await page.locator('#btn-analyze').click();

    // Verify engine subtitle displays accurate fallback instead of hardcoded amazon.nova-lite-v1:0
    await expect(page.locator('#engine-subtitle')).toContainText('Bedrock: Unavailable');
    await expect(page.locator('#engine-subtitle')).not.toContainText('amazon.nova-lite-v1:0');
  });

  test('should display distinct authoritative directive card and unverified AI synthesis for KEV vulnerability', async ({ page }) => {
    await page.route('**/api/vulnerabilities/CVE-2021-44228/triage', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2021-44228',
          status: 'OK',
          retrieved_at: '2026-10-17T12:00:00.000Z',
          decision: {
            priority: 'Critical',
            rationale: 'Active in-the-wild exploitation confirmed via CISA KEV with CVSS 10.0.',
            risk_factors: ['CISA KEV active threat', 'CVSS 10.0'],
            recommended_action: 'Upgrade Apache Log4j dependencies across all microservices.',
            recommendation_source: 'bedrock_synthesis',
            recommendation_is_verified: false,
            recommendation_url: 'https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures',
            authoritative_directive: 'For all affected software assets for which updates exist, the only acceptable remediation actions are: 1) Apply updates; OR 2) remove affected assets from agency networks.',
            authoritative_directive_source: 'cisa_kev',
            authoritative_directive_url: 'https://www.cisa.gov/uscert/ed-22-02-apache-log4j-recommended-mitigation-measures',
            confidence: 0.96,
            confidence_is_calibrated: false,
            confidence_explanation: 'Model-derived Strands Decider 2B confidence score (uncalibrated).',
            evidence_limitations: [
              'Stage 2 operational recommendations are synthesized by AI and have not been independently fact-checked against vendor release registries; operators must validate patch targets before deployment.',
            ],
            engine: 'dual-ai',
            decider_model_id: 'strands-decider-2b',
            bedrock_model_id: 'au.anthropic.claude-sonnet-4-6',
            decider_status: 'success',
            bedrock_status: 'success',
            decided_at: '2026-10-17T12:00:01.000Z',
          },
          normalized: {
            title: 'Log4Shell JNDI RCE',
            description: 'Apache Log4j2 JNDI RCE vulnerability.',
            primary_severity: 'CRITICAL',
            cvss_score: 10.0,
            cvss_version: '3.1',
            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            is_cisa_kev: true,
            cisa_required_action: 'Apply updates.',
            epss_probability: 0.99,
            epss_percentile: 1.0,
            affected_cpe_count: 10,
          },
          provenance: {
            nvd: { source: 'NVD', status: 'AVAILABLE', weaknesses: [], cpe_configurations: [] },
            cisa_kev: { source: 'CISA KEV', status: 'LISTED', is_listed: true },
            epss: { source: 'EPSS', status: 'AVAILABLE', probability: 0.99 },
          },
        }),
      });
    });

    await page.goto('/#analyze');
    await page.locator('#cve-input').fill('CVE-2021-44228');
    await page.locator('#btn-analyze').click();

    // Verify Authoritative Government Directive panel is present and distinct
    await expect(page.locator('#authoritative-directive-panel')).toBeVisible();
    await expect(page.locator('#authoritative-directive-panel')).toContainText('Authoritative Government Directive (CISA KEV)');
    await expect(page.locator('#authoritative-directive-panel')).toContainText('Verified Mandatory Directive');
    await expect(page.locator('#authoritative-directive-text')).toContainText('remove affected assets from agency networks');
    await expect(page.locator('#authoritative-directive-url')).toBeVisible();

    // Verify AI Operational recommendation is separate and marked unverified
    await expect(page.locator('#remediation-source-badge')).toContainText('Bedrock Synthesis (General Guidance)');
    await expect(page.locator('#remediation-unverified-tag')).toContainText('Unverified AI Synthesis');

    // Verify Fact-checking limitation is rendered
    await expect(page.locator('#confidence-limitations-panel')).toContainText('have not been independently fact-checked against vendor release registries');
  });

  test('should prevent out-of-order response overwrite when user submits CVE A and then CVE B', async ({ page }) => {
    // Route for CVE A (Log4Shell) has artificial 600ms delay
    await page.route('**/api/vulnerabilities/CVE-2021-44228/triage', async (route) => {
      await new Promise((r) => setTimeout(r, 600));
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2021-44228',
          status: 'OK',
          decision: {
            priority: 'Critical',
            rationale: 'Late arriving response for CVE-2021-44228',
            risk_factors: ['Late response'],
            recommended_action: 'Action for A',
            confidence: 0.9,
            engine: 'baseline',
            model_id: 'baseline-v1',
            decided_at: new Date().toISOString(),
          },
          normalized: {
            title: 'Apache Log4j2 JNDI RCE',
            description: 'Log4j description',
            primary_severity: 'CRITICAL',
            cvss_score: 10.0,
            is_cisa_kev: true,
            cisa_required_action: 'Patch A',
          },
          provenance: {
            nvd: { source: 'NVD', status: 'AVAILABLE', weaknesses: [], cpe_configurations: [] },
            cisa_kev: { source: 'CISA KEV', status: 'LISTED', is_listed: true },
            epss: { source: 'EPSS', status: 'AVAILABLE', probability: 0.9 },
          },
        }),
      });
    });

    // Route for CVE B (Spring4Shell) responds quickly (50ms)
    await page.route('**/api/vulnerabilities/CVE-2022-22965/triage', async (route) => {
      await new Promise((r) => setTimeout(r, 50));
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2022-22965',
          status: 'OK',
          decision: {
            priority: 'Critical',
            rationale: 'Prompt response for CVE-2022-22965 Spring4Shell',
            risk_factors: ['Spring Framework RCE'],
            recommended_action: 'Action for B',
            confidence: 0.95,
            engine: 'baseline',
            model_id: 'baseline-v1',
            decided_at: new Date().toISOString(),
          },
          normalized: {
            title: 'Spring Framework RCE Spring4Shell',
            description: 'Spring4Shell vulnerability description',
            primary_severity: 'CRITICAL',
            cvss_score: 9.8,
            is_cisa_kev: true,
            cisa_required_action: 'Patch B',
          },
          provenance: {
            nvd: { source: 'NVD', status: 'AVAILABLE', weaknesses: [], cpe_configurations: [] },
            cisa_kev: { source: 'CISA KEV', status: 'LISTED', is_listed: true },
            epss: { source: 'EPSS', status: 'AVAILABLE', probability: 0.9 },
          },
        }),
      });
    });

    await page.goto('/#analyze');

    // 1. Submit CVE A
    await page.locator('#cve-input').fill('CVE-2021-44228');
    await page.locator('#btn-analyze').click();

    // 2. Quickly submit CVE B before A resolves
    await page.locator('#cve-input').fill('CVE-2022-22965');
    await page.locator('#btn-analyze').click();

    // 3. Wait 800ms for both requests to have completed
    await page.waitForTimeout(800);

    // 4. Verify that CVE B is displayed and was NOT overwritten by late CVE A
    await expect(page.locator('#target-cve-id')).toContainText('CVE-2022-22965');
    await expect(page.locator('#target-title')).toContainText('Spring Framework RCE Spring4Shell');
  });

  test('should handle HTTP 429 rate limit error gracefully', async ({ page }) => {
    await page.route('**/api/vulnerabilities/CVE-2021-44228/triage', async (route) => {
      await route.fulfill({
        status: 429,
        contentType: 'application/json',
        headers: { 'Retry-After': '60' },
        body: JSON.stringify({
          detail: 'Rate limit exceeded: maximum 60 triage requests per minute per IP.',
        }),
      });
    });

    await page.goto('/#analyze');
    await page.locator('#cve-input').fill('CVE-2021-44228');
    await page.locator('#btn-analyze').click();

    await expect(page.locator('#state-error')).toBeVisible();
    await expect(page.locator('#state-error')).toContainText('Rate limit exceeded');
  });
});
