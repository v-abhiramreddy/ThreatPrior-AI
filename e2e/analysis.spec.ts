import { test, expect } from '@playwright/test';

test.describe('Vulnerability Analysis Page', () => {
  test.beforeEach(async ({ page }) => {
    // Deterministically mock backend API routes during E2E test runs
    await page.route('**/api/vulnerabilities/CVE-2023-38606**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2023-38606',
          status: 'OK',
          retrieved_at: '2026-10-16T12:00:00Z',
          normalized: {
            title: 'Operation Triangulation Kernel Zero-Day',
            description: 'Apple iOS/macOS kernel memory corruption vulnerability.',
            primary_severity: 'HIGH',
            cvss_score: 8.8,
            cvss_version: '3.1',
            cvss_vector: 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
            is_cisa_kev: true,
            cisa_required_action: 'Apply updates per vendor instructions.',
            cisa_due_date: '2023-08-14',
            epss_probability: 0.8123,
            epss_percentile: 0.945,
            affected_cpe_count: 5,
          },
          provenance: {
            nvd: {
              source: 'NIST NVD API v2.0',
              status: 'AVAILABLE',
              weaknesses: ['CWE-787'],
              cpe_configurations: ['cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*'],
            },
            cisa_kev: {
              source: 'CISA KEV Catalog',
              status: 'LISTED',
              is_listed: true,
              date_added: '2023-07-24',
              due_date: '2023-08-14',
              notes: 'Confirmed listed in CISA Known Exploited Vulnerabilities catalog.',
            },
            epss: {
              source: 'FIRST.org EPSS v3',
              status: 'AVAILABLE',
              probability: 0.8123,
              percentile: 0.945,
              score_date: '2026-10-15',
              interpretive_note: 'Estimated probability of active exploitation in next 30 days.',
            },
          },
          errors: [],
        }),
      });
    });

    await page.route('**/api/vulnerabilities/CVE-9999-00000**', async (route) => {
      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          detail: 'Vulnerability CVE-9999-00000 not found in any upstream intelligence source.',
          errors: ['No record of this CVE identifier was found in NVD, CISA KEV, or EPSS.'],
        }),
      });
    });

    await page.goto('/');
  });


  test('should render default benchmark Log4Shell with correct scores and priority', async ({ page }) => {
    await expect(page.locator('#target-cve-id')).toContainText('CVE-2021-44228');
    await expect(page.locator('#target-title')).toContainText('Log4Shell');

    // 3 Tri-scores
    await expect(page.locator('#metric-cvss')).toContainText('10.0');
    await expect(page.locator('#metric-severity-badge')).toContainText('CRITICAL');
    await expect(page.locator('#metric-cisa')).toContainText('Listed');
    await expect(page.locator('#metric-epss')).toContainText('97.4%');

    // Priority recommendation
    await expect(page.locator('#ai-priority-chip')).toContainText('Priority 1: Immediate Mitigation Required');
    await expect(page.locator('#ai-rationale-text')).toContainText('Log4j2 JNDI remote code execution');

    // Playbook guidance steps
    await expect(page.locator('text=Patch / Dependency Cut')).toBeVisible();
    await expect(page.locator('text=SIEM Egress Query Plan')).toBeVisible();
  });

  test('should switch dynamically when clicking CVE preset pills', async ({ page }) => {
    // Click Apple MMIO preset pill
    await page.locator('button[data-cve="CVE-2023-38606"]').click();
    await expect(page.locator('#target-cve-id')).toContainText('CVE-2023-38606');
    await expect(page.locator('#target-title')).toContainText('Operation Triangulation Kernel Zero-Day');
    await expect(page.locator('#metric-cvss')).toContainText('8.8');
    await expect(page.locator('#metric-severity-badge')).toContainText('HIGH');
    await expect(page.locator('#ai-priority-chip')).toContainText('Priority 2: Expedited Patching Cycle');

    // Click Outlook RCE preset pill
    await page.locator('button[data-cve="CVE-2024-21413"]').click();
    await expect(page.locator('#target-cve-id')).toContainText('CVE-2024-21413');
    await expect(page.locator('#target-title')).toContainText('MonikerLink Outlook Remote Code Execution');
    await expect(page.locator('#metric-cvss')).toContainText('9.8');
    await expect(page.locator('#metric-severity-badge')).toContainText('CRITICAL');
    await expect(page.locator('#ai-priority-chip')).toContainText('Priority 1: Immediate Mitigation Required');
  });

  test('should allow typing a CVE and analyzing or clearing the search input', async ({ page }) => {
    const input = page.locator('#cve-input');

    // Clear input using clear button
    const clearBtn = page.locator('#clear-input-btn');
    await expect(clearBtn).toBeVisible();
    await clearBtn.click();
    await expect(input).toHaveValue('');

    // Type CVE-2023-38606 and trigger analysis
    await input.fill('CVE-2023-38606');
    await page.locator('#btn-analyze').click();

    await expect(page.locator('#target-cve-id')).toContainText('CVE-2023-38606');
    await expect(page.locator('#target-title')).toContainText('Operation Triangulation Kernel Zero-Day');
  });

  test('should display Empty State when submitting an invalid or unindexed CVE', async ({ page }) => {
    const input = page.locator('#cve-input');
    await input.fill('CVE-9999-00000');
    await page.locator('#btn-analyze').click();

    // Verify empty state is displayed
    const emptyState = page.locator('#state-empty');
    await expect(emptyState).toBeVisible();
    await expect(emptyState).toContainText('No Telemetry Ingested (Demo)');

    // Click benchmark restore button
    await emptyState.getByRole('button', { name: 'Load Benchmark CVE-2021-44228' }).click();
    await expect(page.locator('#state-loaded')).toBeVisible();
    await expect(page.locator('#target-cve-id')).toContainText('CVE-2021-44228');
  });

  test('should toggle simulation states via Development Controls', async ({ page }) => {
    // 1. Loading Skeleton
    await page.locator('#toggle-loading-state').click();
    await expect(page.locator('#state-loading')).toBeVisible();

    // 2. Empty State
    await page.locator('#toggle-empty-state').click();
    await expect(page.locator('#state-empty')).toBeVisible();

    // 3. Error State
    await page.locator('#toggle-error-state').click();
    const errorState = page.locator('#state-error');
    await expect(errorState).toBeVisible();
    await expect(errorState).toContainText('Telemetry Feed Simulation Error');

    // Retry from error state restores loaded view
    await errorState.getByRole('button', { name: 'Retry Telemetry Ingestion' }).click();
    await expect(page.locator('#state-loaded')).toBeVisible();
    await expect(page.locator('#target-cve-id')).toContainText('CVE-2021-44228');
  });

  test('should toggle evidence accordions with aria-expanded and visibility', async ({ page }) => {
    const nvdToggle = page.locator('#accordion-nvd button.accordion-toggle');
    const nvdBody = page.locator('#nvd-body');

    // Initially open
    await expect(nvdToggle).toHaveAttribute('aria-expanded', 'true');
    await expect(nvdBody).toBeVisible();

    // Collapse
    await nvdToggle.click();
    await expect(nvdToggle).toHaveAttribute('aria-expanded', 'false');
    await expect(nvdBody).not.toBeVisible();

    // Expand again
    await nvdToggle.click();
    await expect(nvdToggle).toHaveAttribute('aria-expanded', 'true');
    await expect(nvdBody).toBeVisible();

    // CISA KEV toggle
    const cisaToggle = page.locator('#accordion-cisa button.accordion-toggle');
    const cisaBody = page.locator('#cisa-body');
    await expect(cisaToggle).toHaveAttribute('aria-expanded', 'true');
    await cisaToggle.click();
    await expect(cisaToggle).toHaveAttribute('aria-expanded', 'false');
    await expect(cisaBody).not.toBeVisible();

    // EPSS toggle
    const epssToggle = page.locator('#accordion-epss button.accordion-toggle');
    const epssBody = page.locator('#epss-body');
    await expect(epssToggle).toHaveAttribute('aria-expanded', 'true');
    await epssToggle.click();
    await expect(epssToggle).toHaveAttribute('aria-expanded', 'false');
    await expect(epssBody).not.toBeVisible();
  });
});
