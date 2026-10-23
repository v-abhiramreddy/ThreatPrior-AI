import { test, expect } from '@playwright/test';

test.describe('ThreatPrior AI UI Refinements & Functional Integrity', () => {
  test.beforeEach(async ({ page }) => {
    // Provide deterministically mocked responses for CVE-2021-44228
    await page.route('**/api/vulnerabilities/CVE-2021-44228**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2021-44228',
          status: 'OK',
          retrieved_at: '2026-10-16T12:00:00Z',
          normalized: {
            title: 'Log4Shell Apache Log4j2 JNDI Remote Code Execution',
            summary:
              'An unauthenticated attacker can execute arbitrary code remotely by sending malicious lookup strings into application logs. If exploited, attackers can gain full control of the host server, traverse internal networks, and deploy automated ransomware payloads.',
            description:
              'Apache Log4j2 versions 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled.',
            primary_severity: 'CRITICAL',
            cvss_score: 10.0,
            cvss_version: '3.1',
            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            is_cisa_kev: true,
            cisa_required_action:
              'Apply mitigations per vendor instructions or discontinue use of the product if unpatched.',
            cisa_due_date: '2021-12-24',
            epss_probability: 0.9741,
            epss_percentile: 0.998,
            affected_cpe_count: 365,
          },
          provenance: {
            nvd: {
              source: 'NIST NVD API v2.0',
              status: 'AVAILABLE',
              weaknesses: ['CWE-502'],
              cpe_configurations: [
                'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
                'cpe:2.3:a:apache:log4j_core:2.14.1:*:*:*:*:*:*:*',
              ],
            },
            cisa_kev: {
              source: 'CISA KEV Catalog',
              status: 'LISTED',
              is_listed: true,
              date_added: '2021-12-10',
              due_date: '2021-12-24',
              notes: 'Active in-the-wild exploitation confirmed globally.',
            },
            epss: {
              source: 'FIRST.org EPSS v3',
              status: 'AVAILABLE',
              probability: 0.9741,
              percentile: 0.998,
              score_date: '2026-10-15',
              interpretive_note: 'Empirical estimate of exploitation likelihood within 30 days.',
            },
          },
          decision: {
            priority: 'Critical',
            rationale:
              'Log4j2 JNDI remote code execution enables unauthenticated attackers to execute arbitrary code with maximum structural impact. Driven by confirmed CISA KEV active exploitation in the wild and a 97.4% EPSS probability, this vulnerability demands instant mitigation.',
            risk_factors: [
              'Confirmed active exploitation in the wild (CISA KEV listed)',
              'Catastrophic structural impact (CVSS 10.0 Critical)',
              'High empirical weaponization probability (EPSS 97.4%)',
            ],
            recommended_action:
              'Upgrade Apache Log4j dependencies to version 2.17.1 or apply JVM parameter -Dlog4j2.formatMsgNoLookups=true.',
            confidence: 0.94,
            confidence_is_calibrated: false,
            engine: 'dual-ai',
            decider_model_id: 'strands-decider-2b',
            bedrock_model_id: 'au.anthropic.claude-sonnet-4-6',
            decider_status: 'success',
            bedrock_status: 'success',
            decided_at: '2026-10-16T12:00:00Z',
          },
          errors: [],
        }),
      });
    });
  });

  test('Global Contact Us button in footer opens accessible modal with working actions', async ({ page }) => {
    await page.goto('/');

    const contactBtn = page.locator('#footer-contact-us-btn');
    await expect(contactBtn).toBeVisible();
    await expect(contactBtn).toContainText('Contact Us');

    // Click Contact Us
    await contactBtn.click();

    // Modal dialog is displayed
    const modal = page.locator('[role="dialog"][aria-labelledby="contact-modal-heading"]');
    await expect(modal).toBeVisible();
    await expect(page.locator('#contact-modal-heading')).toHaveText('Get in Touch');
    await expect(modal).toContainText('Have questions, feedback, or suggestions about ThreatPrior AI?');
    await expect(page.locator('#contact-modal-email')).toHaveText('v.abhiramreddy2007@gmail.com');

    // Send Email button has mailto link
    const sendEmailLink = page.locator('#contact-send-email-btn');
    await expect(sendEmailLink).toBeVisible();
    await expect(sendEmailLink).toHaveAttribute('href', 'mailto:v.abhiramreddy2007@gmail.com?subject=ThreatPrior%20AI%20Inquiry');

    // Grant clipboard permissions for automated test browser context
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write']).catch(() => {});

    // Copy Email button works
    const copyEmailBtn = page.locator('#contact-copy-email-btn');
    await expect(copyEmailBtn).toBeVisible();
    await copyEmailBtn.click();
    await expect(modal).toContainText(/Email copied to clipboard!|Please copy manually/);

    // Escape closes modal
    await page.keyboard.press('Escape');
    await expect(modal).not.toBeVisible();

    // Reopen and close via close button
    await contactBtn.click();
    await expect(modal).toBeVisible();
    await page.locator('#contact-modal-close-btn').click();
    await expect(modal).not.toBeVisible();
  });

  test('Vulnerability Analysis heading & subtitle match approved copy', async ({ page }) => {
    await page.goto('/#analyze');

    const heading = page.locator('#analysis-page-heading');
    await expect(heading).toBeVisible();
    await expect(heading).toHaveText('Understand the risk. Act with confidence.');

    const subtitle = page.locator('#analysis-page-subtitle');
    await expect(subtitle).toBeVisible();
    await expect(subtitle).toHaveText(
      'Analyze vulnerabilities using AI-driven prioritization, trusted threat intelligence, and evidence-based remediation guidance.'
    );
  });

  test('Analysis page initial state is empty without automatic CVE analysis', async ({ page }) => {
    await page.goto('/#analyze');

    await expect(page.locator('#state-empty')).toBeVisible();
    await expect(page.locator('#target-cve-id')).not.toBeVisible();
    await expect(page.locator('#state-loaded')).not.toBeVisible();
  });

  test('CVE overview displays Operational Summary and original description at top without duplicate Technical Description section', async ({ page }) => {
    await page.goto('/#analyze');

    // Load offline demo fixture
    await page.locator('#btn-pill-demo-fixture').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    // Original description displayed at top below CVE ID
    const topDesc = page.locator('#target-cve-desc');
    await expect(topDesc).toBeVisible();
    await expect(topDesc).toContainText('Log4j2 JNDI Remote Code Execution');

    // Operational summary card
    const opSummary = page.locator('#cve-operational-summary');
    await expect(opSummary).toBeVisible();
    await expect(opSummary).toContainText('An unauthenticated attacker can execute arbitrary code remotely');

    // Redundant Technical Description accordion is removed
    const toggleBtn = page.locator('#btn-toggle-tech-desc');
    await expect(toggleBtn).not.toBeVisible();

    const techDescContent = page.locator('#technical-description-panel');
    await expect(techDescContent).not.toBeVisible();
  });

  test('Export Dossier button has tooltip and triggers JSON report download', async ({ page }) => {
    await page.goto('/#analyze');
    await page.locator('#btn-pill-demo-fixture').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    const exportBtn = page.locator('#btn-export-dossier');
    await expect(exportBtn).toBeVisible();
    await expect(exportBtn).toHaveAttribute('title', 'Download report');

    // Test download event
    const downloadPromise = page.waitForEvent('download');
    await exportBtn.click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe('cve-2021-44228_dossier.json');
  });

  test('Watchlist toggle adds/removes CVE and persists in localStorage with modal management', async ({ page }) => {
    await page.goto('/#analyze');
    await page.locator('#btn-pill-demo-fixture').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    const watchlistBtn = page.locator('#btn-toggle-watchlist');
    await expect(watchlistBtn).toBeVisible();
    await expect(watchlistBtn).toHaveAttribute('title', 'Track this CVE');
    await expect(watchlistBtn).toContainText('Watchlist');

    // Add to watchlist
    await watchlistBtn.click();
    await expect(watchlistBtn).toContainText('Tracked');

    // Verify localStorage persistence
    const stored = await page.evaluate(() => localStorage.getItem('threatprior_watchlist_cves'));
    expect(stored).toBeTruthy();
    expect(stored).toContain('CVE-2021-44228');

    // Open Watchlist modal via Quick Targets button
    const viewWatchlistBtn = page.locator('#btn-view-watchlist');
    await expect(viewWatchlistBtn).toBeVisible();
    await expect(viewWatchlistBtn).toContainText('Watchlist (1)');
    await viewWatchlistBtn.click();

    // Verify modal is open and shows tracked CVE
    const modal = page.locator('[role="dialog"][aria-labelledby="watchlist-modal-title"]');
    await expect(modal).toBeVisible();
    await expect(modal).toContainText('CVE-2021-44228');

    // Close modal via Escape
    await page.keyboard.press('Escape');
    await expect(modal).not.toBeVisible();

    // Untrack via header button
    await watchlistBtn.click();
    await expect(watchlistBtn).toContainText('Watchlist');

    const storedAfter = await page.evaluate(() => localStorage.getItem('threatprior_watchlist_cves'));
    expect(storedAfter).toBe('[]');
  });

  test('Dual-Model AI card displays uncalibrated score explanation and model badges', async ({ page }) => {
    await page.goto('/#analyze');
    await page.locator('#btn-pill-demo-fixture').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    const calibStatus = page.locator('#provenance-calibration-status');
    await expect(calibStatus).toBeVisible();
    await expect(calibStatus).toContainText('Uncalibrated Score');
    await expect(calibStatus).toHaveAttribute('title', /normalized distribution concentration/);

    await expect(page.locator('#provenance-decider-status')).toContainText('Decider 2B');
    await expect(page.locator('#provenance-bedrock-status')).toContainText('Bedrock');
  });

  test('Remediation playbook uses 3-column balanced layout with policy target SLA', async ({ page }) => {
    await page.goto('/#analyze');
    await page.locator('#btn-pill-demo-fixture').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    // Check SLA label mentions policy target
    const playbookHeader = page.locator('span:has-text("Recommended Remediation Playbook")').locator('..');
    await expect(playbookHeader).toContainText('Target SLA (Policy Target)');

    // 3 steps visible
    await expect(page.locator('text=Immediate Remediation / Isolation')).toBeVisible();
    await expect(page.locator('text=Vulnerable Asset Inventory Discovery')).toBeVisible();
    await expect(page.locator('text=Egress Monitoring & Exploit Detection')).toBeVisible();
  });

  test('CVSS vector metrics are formatted as scanable single-line chips', async ({ page }) => {
    await page.goto('/#analyze');
    await page.locator('#btn-pill-demo-fixture').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    const nvdAccordion = page.locator('#accordion-nvd');
    await expect(nvdAccordion).toBeVisible();

    // Check single-line formatted chips
    await expect(nvdAccordion).toContainText('AV — Network');
    await expect(nvdAccordion).toContainText('AC — Low');
    await expect(nvdAccordion).toContainText('PR — None');
  });

  test('CPE signatures section has copy button and expands without overflow', async ({ page }) => {
    await page.goto('/#analyze');
    await page.locator('#btn-pill-demo-fixture').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    const toggleCpeBtn = page.locator('#btn-toggle-cpe-signatures');
    await expect(toggleCpeBtn).toBeVisible();
    await expect(toggleCpeBtn).toContainText('View CPE Signatures');

    await toggleCpeBtn.click();
    await expect(page.locator('#cpe-signatures-body')).toBeVisible();
    await expect(page.locator('#cpe-signatures-body')).toContainText('cpe:2.3:a:apache:log4j');
  });

  test('External links point to valid verified destinations', async ({ page }) => {
    await page.goto('/#analyze');
    await page.locator('#btn-pill-demo-fixture').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    // NVD source link
    const nvdLink = page.locator('#nvd-source-link');
    await expect(nvdLink).toHaveAttribute('href', 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228');
    await expect(nvdLink).toHaveAttribute('target', '_blank');

    // CISA advisory link
    const cisaLink = page.locator('#cisa-advisory-link');
    await expect(cisaLink).toHaveAttribute('href', /.*cisa\.gov.*/);
    await expect(cisaLink).toHaveAttribute('target', '_blank');

    // EPSS source link
    const epssLink = page.locator('#epss-source-link');
    await expect(epssLink).toHaveAttribute('href', 'https://www.first.org/epss/');
    await expect(epssLink).toHaveAttribute('target', '_blank');

    // Directive reference link
    const directiveLink = page.locator('#authoritative-directive-url');
    await expect(directiveLink).toHaveAttribute('href', /.*cisa\.gov.*/);
  });

  test('Update 1: All three vulnerability examples display distinct, CVE-specific operational summaries and complete technical descriptions', async ({ page }) => {
    // Mock responses for all 3 presets
    await page.route('**/api/vulnerabilities/CVE-2023-38606/**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2023-38606',
          status: 'OK',
          retrieved_at: '2026-10-23T10:00:00Z',
          normalized: {
            title: 'Operation Triangulation Kernel Zero-Day',
            summary:
              'A malicious local app can manipulate hardware memory-mapped registers to bypass core operating system protections. This grants an attacker unrestricted kernel read/write access, enabling stealthy installation of surveillance spyware on compromised devices.',
            description:
              'An app may be able to modify sensitive kernel state. Apple is aware of a report that this issue may have been actively exploited against versions of iOS released before iOS 15.7. macOS Ventura 13.5, iOS 16.6 and iPadOS 16.6, watchOS 9.6, tvOS 16.6, iOS 15.7.8 and iPadOS 15.7.8, macOS Monterey 12.6.8, macOS Big Sur 11.7.9.',
            primary_severity: 'HIGH',
            cvss_score: 8.8,
            cvss_version: '3.1',
            is_cisa_kev: true,
            affected_cpe_count: 12,
          },
          provenance: {
            nvd: { source: 'NIST NVD API v2.0', status: 'AVAILABLE' },
            cisa_kev: { source: 'CISA KEV Catalog', status: 'LISTED', is_listed: true, notes: 'Active in-the-wild.' },
            epss: { source: 'FIRST.org EPSS v3', status: 'AVAILABLE', probability: 0.821, percentile: 0.974 },
          },
          decision: {
            priority: 'High',
            rationale: 'Active zero day in wild.',
            recommended_action: 'Update Apple devices',
            confidence: 0.9,
            engine: 'dual-ai',
            decided_at: '2026-10-23T10:00:00Z',
          },
          errors: [],
        }),
      });
    });

    await page.route('**/api/vulnerabilities/CVE-2024-21413/**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2024-21413',
          status: 'OK',
          retrieved_at: '2026-10-23T10:00:00Z',
          normalized: {
            title: 'MonikerLink Outlook Remote Code Execution',
            summary:
              'Specially crafted email links bypass Office security boundaries to trigger background network authentication against an external server. This silently exposes corporate Windows login credentials and enables unauthorized code execution, even when a user merely previews an email.',
            description:
              'Microsoft Outlook Remote Code Execution Vulnerability (MonikerLink). An attacker who successfully exploited this vulnerability could bypass Office Protected View and execute arbitrary code. Exploitation requires sending an email containing a specially crafted link that bypasses Protected View protocol checks when clicked or previewed.',
            primary_severity: 'CRITICAL',
            cvss_score: 9.8,
            cvss_version: '3.1',
            is_cisa_kev: true,
            affected_cpe_count: 15,
          },
          provenance: {
            nvd: { source: 'NIST NVD API v2.0', status: 'AVAILABLE' },
            cisa_kev: { source: 'CISA KEV Catalog', status: 'LISTED', is_listed: true, notes: 'Active in-the-wild.' },
            epss: { source: 'FIRST.org EPSS v3', status: 'AVAILABLE', probability: 0.889, percentile: 0.985 },
          },
          decision: {
            priority: 'Critical',
            rationale: 'Active exploitation in wild.',
            recommended_action: 'Deploy updates',
            confidence: 0.95,
            engine: 'dual-ai',
            decided_at: '2026-10-23T10:00:00Z',
          },
          errors: [],
        }),
      });
    });

    await page.goto('/#analyze');

    const examples = [
      {
        cve: 'CVE-2021-44228',
        selector: '[data-cve="CVE-2021-44228"]',
        expectedSummarySnippet: 'An unauthenticated attacker can execute arbitrary code remotely',
        expectedTechDescSnippet: 'versions 2.0-beta9 through 2.15.0',
      },
      {
        cve: 'CVE-2023-38606',
        selector: '[data-cve="CVE-2023-38606"]',
        expectedSummarySnippet: 'A malicious local app can manipulate hardware memory-mapped registers',
        expectedTechDescSnippet: 'Apple is aware of a report that this issue may have been actively exploited',
      },
      {
        cve: 'CVE-2024-21413',
        selector: '[data-cve="CVE-2024-21413"]',
        expectedSummarySnippet: 'Specially crafted email links bypass Office security boundaries',
        expectedTechDescSnippet: 'Microsoft Outlook Remote Code Execution Vulnerability (MonikerLink)',
      },
    ];

    for (const item of examples) {
      await page.locator(item.selector).click();
      await page.locator('#btn-analyze').click();
      await expect(page.locator('#state-loaded')).toBeVisible();

      // Check operational summary
      const opSummaryEl = page.locator('#cve-operational-summary');
      await expect(opSummaryEl).toBeVisible();
      const opSummaryText = (await opSummaryEl.textContent()) || '';
      expect(opSummaryText).toContain(item.expectedSummarySnippet);

      // Verify that original description is visible at the top
      const topDescEl = page.locator('#target-cve-desc');
      await expect(topDescEl).toBeVisible();

      // Redundant technical description accordion is removed from UI
      const toggleBtn = page.locator('#btn-toggle-tech-desc');
      await expect(toggleBtn).not.toBeVisible();
      const techPanel = page.locator('#technical-description-panel');
      await expect(techPanel).not.toBeVisible();
    }
  });

  test('Update 2: CISA KEV Cached-Catalog Warning displays exact 403 copy, metadata, and handles other failures', async ({ page }) => {
    // 1. HTTP 403 with cached fallback
    await page.route('**/api/vulnerabilities/CVE-2021-44228/**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2021-44228',
          status: 'PARTIAL',
          retrieved_at: '2026-10-23T10:00:00Z',
          normalized: {
            title: 'Log4Shell Apache Log4j2 JNDI Remote Code Execution',
            description: 'Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP endpoints.',
            summary:
              'An unauthenticated attacker can execute arbitrary code remotely by sending malicious lookup strings into application logs. If exploited, attackers can gain full control of the host server, traverse internal networks, and deploy automated ransomware payloads.',
            primary_severity: 'CRITICAL',
            cvss_score: 10.0,
            cvss_version: '3.1',
            is_cisa_kev: true,
            affected_cpe_count: 365,
          },
          provenance: {
            nvd: { source: 'NIST NVD API v2.0', status: 'AVAILABLE' },
            cisa_kev: {
              source: 'CISA KEV Catalog',
              status: 'LISTED',
              is_listed: true,
              is_cached: true,
              catalog_version: '2026.10.15',
              catalog_date_released: '2026-10-15',
              last_refreshed_at: '2026-10-22T08:30:00Z',
              error_message: 'CISA KEV HTTP 403: Forbidden',
              notes: 'Active in-the-wild exploitation confirmed.',
            },
            epss: { source: 'FIRST.org EPSS v3', status: 'AVAILABLE', probability: 0.974, percentile: 0.998 },
          },
          decision: {
            priority: 'Critical',
            rationale: 'Active exploitation in wild.',
            recommended_action: 'Upgrade log4j',
            confidence: 0.95,
            engine: 'dual-ai',
            decided_at: '2026-10-23T10:00:00Z',
          },
          errors: ['CISA KEV HTTP 403: Forbidden'],
        }),
      });
    });

    await page.goto('/#analyze');
    await page.locator('#cve-input').fill('CVE-2021-44228');
    await page.locator('#btn-analyze').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    // Ensure CISA accordion is expanded
    const cisaBody = page.locator('#cisa-body');
    if (!(await cisaBody.isVisible())) {
      await page.locator('#accordion-cisa button.accordion-toggle').click();
    }
    await expect(cisaBody).toBeVisible();

    const cisaWarning = page.locator('#cisa-cached-warning');
    await expect(cisaWarning).toBeVisible();

    // Verify exact 403 copy
    await expect(cisaWarning).toContainText('Cached catalog · Live refresh unavailable');
    await expect(cisaWarning).toContainText('The upstream CISA KEV refresh returned HTTP 403. Displaying the cached catalog instead.');

    // Verify source metadata
    await expect(cisaWarning).toContainText('Cached Catalog Version: 2026.10.15');
    await expect(cisaWarning).toContainText('Catalog Release Date: 2026-10-15');
    await expect(cisaWarning).toContainText('Last Successful Retrieval:');

    // 2. Timeout failure with cached fallback
    await page.route('**/api/vulnerabilities/CVE-2023-38606/**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2023-38606',
          status: 'PARTIAL',
          retrieved_at: '2026-10-23T10:00:00Z',
          normalized: {
            title: 'Operation Triangulation Kernel Zero-Day',
            description: 'Apple iOS/macOS MMIO exploit.',
            summary: 'A local application may be able to modify sensitive kernel state.',
            primary_severity: 'HIGH',
            cvss_score: 8.8,
            is_cisa_kev: true,
            affected_cpe_count: 12,
          },
          provenance: {
            nvd: { source: 'NIST NVD API v2.0', status: 'AVAILABLE' },
            cisa_kev: {
              source: 'CISA KEV Catalog',
              status: 'TIMEOUT',
              is_listed: true,
              is_cached: true,
              catalog_version: '2026.10.15',
              error_message: 'CISA KEV query timed out after 10s',
              notes: 'Active in-the-wild exploitation confirmed.',
            },
            epss: { source: 'FIRST.org EPSS v3', status: 'AVAILABLE', probability: 0.82, percentile: 0.97 },
          },
          decision: {
            priority: 'High',
            rationale: 'Active exploitation in wild.',
            recommended_action: 'Update Apple devices',
            confidence: 0.90,
            engine: 'dual-ai',
            decided_at: '2026-10-23T10:00:00Z',
          },
          errors: ['CISA KEV query timed out after 10s'],
        }),
      });
    });

    await page.locator('#cve-input').fill('CVE-2023-38606');
    await page.locator('#btn-analyze').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    if (!(await page.locator('#cisa-body').isVisible())) {
      await page.locator('#accordion-cisa button.accordion-toggle').click();
    }
    const timeoutWarning = page.locator('#cisa-cached-warning');
    await expect(timeoutWarning).toBeVisible();
    await expect(timeoutWarning).toContainText('Cached catalog · Live refresh failed');
    await expect(timeoutWarning).toContainText('The upstream CISA KEV refresh timed out. Displaying the cached catalog instead.');

    // 3. Successful live refresh without cache warning
    await page.route('**/api/vulnerabilities/CVE-2024-21413/**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2024-21413',
          status: 'OK',
          retrieved_at: '2026-10-23T10:00:00Z',
          normalized: {
            title: 'MonikerLink Outlook Remote Code Execution',
            description: 'Microsoft Outlook Remote Code Execution.',
            summary: 'A link handling vulnerability in Microsoft Outlook allows an attacker to bypass Office Protected View.',
            primary_severity: 'CRITICAL',
            cvss_score: 9.8,
            is_cisa_kev: true,
            affected_cpe_count: 15,
          },
          provenance: {
            nvd: { source: 'NIST NVD API v2.0', status: 'AVAILABLE' },
            cisa_kev: {
              source: 'CISA KEV Catalog',
              status: 'LISTED',
              is_listed: true,
              is_cached: false,
              catalog_version: '2026.10.15',
              notes: 'Active in-the-wild exploitation confirmed.',
            },
            epss: { source: 'FIRST.org EPSS v3', status: 'AVAILABLE', probability: 0.88, percentile: 0.98 },
          },
          decision: {
            priority: 'Critical',
            rationale: 'Active exploitation in wild.',
            recommended_action: 'Deploy security updates',
            confidence: 0.95,
            engine: 'dual-ai',
            decided_at: '2026-10-23T10:00:00Z',
          },
          errors: [],
        }),
      });
    });

    await page.locator('#cve-input').fill('CVE-2024-21413');
    await page.locator('#btn-analyze').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    if (!(await page.locator('#cisa-body').isVisible())) {
      await page.locator('#accordion-cisa button.accordion-toggle').click();
    }
    await expect(page.locator('#cisa-cached-warning')).not.toBeVisible();
  });

  test('Update 3: Refined Risk Policy Validation typography, non-repetitive trigger, and factual evidence rows', async ({ page }) => {
    await page.goto('/#analyze');

    // Load offline demo fixture (CVE-2021-44228) with policy disagreement
    await page.locator('#btn-pill-demo-fixture').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    const panel = page.locator('#risk-validation-panel');
    await expect(panel).toBeVisible();

    // Section heading: Evidence-Based Risk Policy Validation
    await expect(panel).toContainText('Evidence-Based Risk Policy Validation');
    await expect(panel).toContainText('Rules v2026.1-policy');

    // Status badge: Status: disagreement
    await expect(panel).toContainText('Status: disagreement');

    // Disagreement banner heading and copy
    const alert = page.locator('#validation-disagreement-alert');
    await expect(alert).toBeVisible();
    await expect(alert).toContainText('Model Decision vs. Deterministic Policy Discrepancy');
    await expect(alert).toContainText(
      'The AI assigned High, while the deterministic policy evaluates the evidence as Critical. This is an independent rules-based assessment, not a second AI model.'
    );

    // Below banner: concise deterministic policy trigger explanation without repeating the discrepancy
    const explanationEl = page.locator('#validation-explanation-text');
    await expect(explanationEl).toBeVisible();
    await expect(explanationEl).toContainText('Deterministic Policy Trigger: Confirmed CISA KEV active exploitation combined with critical impact');
    // Ensure it does not repeat the discrepancy phrase
    const explanationText = (await explanationEl.textContent()) || '';
    expect(explanationText).not.toContain('Model Decision vs. Deterministic Policy Discrepancy');

    // Factual evidence rows: NVD, CISA, EPSS
    const findings = page.locator('#validation-findings-list');
    await expect(findings).toBeVisible();
    await expect(findings).toContainText('NVD CVSS Base Score: 10.0');
    await expect(findings).toContainText('CISA KEV: Listed as confirmed active threat');
    await expect(findings).toContainText('EPSS Likelihood: 97.4%');

    // Confirm AI-assigned priority remains authoritative and unchanged by policy check
    const aiPriority = page.locator('#ai-priority-chip');
    await expect(aiPriority).toContainText('Priority 1'); // Strands Decider Priority 1 in demo fixture
  });

  test('Refinement 2: Consolidated Remediation Validation section displays dynamic status, is collapsed by default, and isolates unverified patch targets', async ({ page }) => {
    await page.goto('/#analyze');
    await page.locator('#btn-pill-demo-fixture').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    const panel = page.locator('#confidence-limitations-panel');
    await expect(panel).toBeVisible();

    // Verify uncalibrated confidence explanation and prominent percentage
    await expect(panel).toContainText('94.0% Confidence');
    await expect(page.locator('#confidence-explanation-text')).toContainText('uncalibrated');

    // Consolidated Remediation Validation section exists
    const remSection = page.locator('#remediation-validation-section');
    await expect(remSection).toBeVisible();
    await expect(remSection).toContainText('Remediation Validation');

    // Check dynamic concise status indicator (not hardcoded)
    const statusBadge = page.locator('#remediation-validation-status-badge');
    await expect(statusBadge).toBeVisible();
    await expect(statusBadge).toContainText('require verification');

    // Verified collapsed by default
    const remPanel = page.locator('#remediation-validation-panel');
    await expect(remPanel).not.toBeVisible();

    // Expand accordion
    const toggleBtn = page.locator('#btn-toggle-remediation-validation');
    await toggleBtn.click();
    await expect(remPanel).toBeVisible();

    // Check consolidated vendor advisory & target version warning
    const warning = page.locator('#remediation-validation-warning');
    await expect(warning).toBeVisible();
    await expect(warning).toContainText('AI-generated remediation recommendations require verification against official vendor advisories');
    await expect(warning).toContainText('Operators must validate patch targets against vendor release notes');

    // Verify unverified version suggestion is inside this consolidated section
    const remList = page.locator('#remediation-validation-list');
    await expect(remList).toBeVisible();
    await expect(remList).toContainText('Extrapolated target patch version "2.17.1"');

    // Toggle collapse again
    await toggleBtn.click();
    await expect(remPanel).not.toBeVisible();
  });

  test('Refinement 1 & 3: Operational summary fallback and risk policy validation status badge layout', async ({ page }) => {
    // Mock response with sparse description that triggers the operational summary fallback
    await page.route('**/api/vulnerabilities/CVE-2099-0001/**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2099-0001',
          status: 'OK',
          retrieved_at: '2026-10-23T10:00:00Z',
          normalized: {
            title: 'CVE-2099-0001 Sparse Record',
            summary: 'Operational Summary Fallback: Standardized plain-English overview unavailable from source telemetry. Refer to authoritative Technical Description below.',
            description: 'Unspecified generic component issue.',
            primary_severity: 'MEDIUM',
            cvss_score: 5.0,
            cvss_version: '3.1',
            is_cisa_kev: false,
            affected_cpe_count: 1,
          },
          provenance: {
            nvd: { source: 'NIST NVD API v2.0', status: 'AVAILABLE' },
            cisa_kev: { source: 'CISA KEV Catalog', status: 'NOT_LISTED', is_listed: false, notes: 'Not listed.' },
            epss: { source: 'FIRST.org EPSS v3', status: 'AVAILABLE', probability: 0.02, percentile: 0.1 },
          },
          decision: {
            priority: 'Medium',
            rationale: 'Moderate impact.',
            recommended_action: 'Review telemetry',
            confidence: 0.8,
            engine: 'dual-ai',
            decided_at: '2026-10-23T10:00:00Z',
          },
          errors: [],
        }),
      });
    });

    await page.goto('/#analyze');
    await page.locator('#cve-input').fill('CVE-2099-0001');
    await page.locator('#btn-analyze').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    // Verify labelled fallback text is displayed
    const opSummary = page.locator('#cve-operational-summary');
    await expect(opSummary).toBeVisible();
    await expect(opSummary).toContainText('Operational Summary Fallback: Standardized plain-English overview unavailable from source telemetry');

    // Load offline demo fixture to check policy validation heading and status badge layout
    await page.locator('#btn-pill-demo-fixture').click();
    await expect(page.locator('#state-loaded')).toBeVisible();

    const statusBadge = page.locator('#risk-policy-status-badge');
    await expect(statusBadge).toBeVisible();
    await expect(statusBadge).toHaveClass(/whitespace-nowrap/);
    await expect(statusBadge).toContainText('Status: disagreement');
  });
});
