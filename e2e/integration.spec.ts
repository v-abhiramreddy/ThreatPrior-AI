import { test, expect } from '@playwright/test';

test.describe('Frontend–Backend Integration Tests', () => {
  test('should render live-mode vulnerability analysis with full upstream provenance', async ({ page }) => {
    // Mock successful live backend response
    await page.route('**/api/vulnerabilities/CVE-2021-44228**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2021-44228',
          status: 'OK',
          retrieved_at: '2026-10-16T12:30:00.000Z',
          normalized: {
            title: 'Apache Log4j2 Remote Code Execution Vulnerability',
            description: 'Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.',
            primary_severity: 'CRITICAL',
            cvss_score: 10.0,
            cvss_version: '3.1',
            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
            is_cisa_kev: true,
            cisa_required_action: 'Apply updates per vendor instructions.',
            cisa_due_date: '2021-12-24',
            epss_probability: 0.99999,
            epss_percentile: 1.0,
            affected_cpe_count: 365,
          },
          provenance: {
            nvd: {
              source: 'NIST National Vulnerability Database API v2.0',
              status: 'AVAILABLE',
              retrieved_at: '2026-10-16T12:30:00.000Z',
              vuln_status: 'Analyzed',
              published_date: '2021-12-10T10:15:08.767',
              last_modified_date: '2024-08-01T15:00:00.000',
              cvss_v31: {
                base_score: 10.0,
                severity: 'CRITICAL',
                vector_string: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
              },
              weaknesses: ['CWE-502', 'CWE-400'],
              cpe_configurations: ['cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'],
            },
            cisa_kev: {
              source: 'CISA Known Exploited Vulnerabilities Catalog',
              status: 'LISTED',
              retrieved_at: '2026-10-16T12:30:00.000Z',
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
              retrieved_at: '2026-10-16T12:30:00.000Z',
              model_version: '1.0',
              probability: 0.99999,
              percentile: 1.0,
              score_date: '2026-10-15',
              interpretive_note: 'Estimated probability of active exploitation in next 30 days based on observed threat telemetry.',
            },
          },
          errors: [],
        }),
      });
    });

    await page.goto('/');

    // Type and click analyze
    await page.locator('#cve-input').fill('CVE-2021-44228');
    await page.locator('#btn-analyze').click();

    // Verify live mode indicators
    await expect(page.locator('#pipeline-mode-badge')).toContainText('Live Vulnerability Intelligence Feed');
    await expect(page.locator('#demo-mode-indicator')).toContainText('Live Intelligence');
    await expect(page.locator('#data-source-disclaimer')).toContainText('Live feed');
    await expect(page.locator('#provenance-strip')).toBeVisible();
    await expect(page.locator('#provenance-strip')).toContainText('NVD: AVAILABLE');
    await expect(page.locator('#provenance-strip')).toContainText('CISA KEV: LISTED');
    await expect(page.locator('#provenance-strip')).toContainText('EPSS: AVAILABLE');

    // Verify live scores
    await expect(page.locator('#metric-cvss')).toContainText('10.0');
    await expect(page.locator('#metric-cisa')).toContainText('Listed');
    await expect(page.locator('#metric-epss')).toContainText('100.0%');

    // Verify disclaimers
    await expect(page.locator('#state-loaded')).toContainText('LIVE TELEMETRY AUDIT');
    await expect(page.locator('#epss-forecast-disclaimer')).toContainText('Empirical Threat Forecast');
  });

  test('should display partial failure when upstream source is rate limited', async ({ page }) => {
    // Mock partial failure (NVD rate limited, CISA and EPSS successful)
    await page.route('**/api/vulnerabilities/CVE-2022-22965**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2022-22965',
          status: 'PARTIAL',
          retrieved_at: '2026-10-16T12:35:00.000Z',
          normalized: {
            title: 'Spring Framework Remote Code Execution (Spring4Shell)',
            description: 'Vulnerability telemetry record.',
            primary_severity: 'UNKNOWN',
            cvss_score: null,
            cvss_version: null,
            cvss_vector: null,
            is_cisa_kev: true,
            cisa_required_action: 'Apply updates per vendor instructions.',
            cisa_due_date: '2022-04-25',
            epss_probability: 0.965,
            epss_percentile: 0.99,
            affected_cpe_count: 0,
          },
          provenance: {
            nvd: {
              source: 'NIST NVD',
              status: 'RATE_LIMITED',
              error_message: 'NVD API rate limit exceeded (HTTP 429).',
              weaknesses: [],
              cpe_configurations: [],
            },
            cisa_kev: {
              source: 'CISA KEV',
              status: 'LISTED',
              is_listed: true,
              date_added: '2022-04-04',
              notes: 'Confirmed listed in CISA KEV.',
            },
            epss: {
              source: 'FIRST.org EPSS',
              status: 'AVAILABLE',
              probability: 0.965,
              percentile: 0.99,
              score_date: '2026-10-15',
              interpretive_note: 'Estimated probability.',
            },
          },
          errors: ['NVD: NVD API rate limit exceeded (HTTP 429).'],
        }),
      });
    });

    await page.goto('/');
    await page.locator('#cve-input').fill('CVE-2022-22965');
    await page.locator('#btn-analyze').click();

    // Verify partial telemetry badge
    await expect(page.locator('#pipeline-mode-badge')).toContainText('PARTIAL TELEMETRY');
    await expect(page.locator('#provenance-strip')).toContainText('NVD: RATE_LIMITED');
    await expect(page.locator('#provenance-strip')).toContainText('CISA KEV: LISTED');
    await expect(page.locator('#provenance-strip')).toContainText('NVD API rate limit exceeded');
  });

  test('should display CISA absence notice with explicit non-safety disclaimer when NOT_LISTED', async ({ page }) => {
    // Mock CVE that is NOT in CISA KEV
    await page.route('**/api/vulnerabilities/CVE-2023-38546**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2023-38546',
          status: 'OK',
          retrieved_at: '2026-10-16T12:40:00.000Z',
          normalized: {
            title: 'curl SOCKS5 Heap Buffer Overflow',
            description: 'Heap buffer overflow in curl.',
            primary_severity: 'HIGH',
            cvss_score: 7.5,
            cvss_version: '3.1',
            cvss_vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
            is_cisa_kev: false,
            cisa_required_action: null,
            cisa_due_date: null,
            epss_probability: 0.045,
            epss_percentile: 0.72,
            affected_cpe_count: 1,
          },
          provenance: {
            nvd: { source: 'NIST NVD', status: 'AVAILABLE', weaknesses: ['CWE-122'], cpe_configurations: [] },
            cisa_kev: {
              source: 'CISA KEV',
              status: 'NOT_LISTED',
              is_listed: false,
              notes: 'Not listed in CISA KEV catalog. Absence from this catalog indicates only that CISA has not confirmed in-wild exploitation for this entry; it does not indicate absence of risk or proof of safety.',
            },
            epss: { source: 'FIRST.org EPSS', status: 'AVAILABLE', probability: 0.045, percentile: 0.72, interpretive_note: 'Estimated probability.' },
          },
          errors: [],
        }),
      });
    });

    await page.goto('/');
    await page.locator('#cve-input').fill('CVE-2023-38546');
    await page.locator('#btn-analyze').click();

    // Verify CISA KEV shows Not Listed
    await expect(page.locator('#metric-cisa')).toContainText('Not Listed');
    // Verify explicit absence disclaimer
    const disclaimer = page.locator('#cisa-absence-disclaimer');
    await expect(disclaimer).toBeVisible();
    await expect(disclaimer).toContainText('Absence indicates only that CISA has not confirmed in-wild exploitation');
    await expect(disclaimer).toContainText('does not indicate absence of risk or proof of safety');
  });

  test('should handle invalid CVE identifier (HTTP 400)', async ({ page }) => {
    await page.route('**/api/vulnerabilities/INVALID-INPUT**', async (route) => {
      await route.fulfill({
        status: 400,
        contentType: 'application/json',
        body: JSON.stringify({
          detail: "Invalid CVE identifier format: 'INVALID-INPUT'. Expected standard pattern 'CVE-YYYY-NNNN+'.",
        }),
      });
    });

    await page.goto('/');
    await page.locator('#cve-input').fill('INVALID-INPUT');
    await page.locator('#btn-analyze').click();

    // Verify empty/rejection state
    await expect(page.locator('#state-empty')).toBeVisible();
    await expect(page.locator('#state-empty')).toContainText('Invalid CVE identifier format');
  });

  test('should handle unknown CVE identifier (HTTP 404)', async ({ page }) => {
    await page.route('**/api/vulnerabilities/CVE-2099-99999**', async (route) => {
      await route.fulfill({
        status: 404,
        contentType: 'application/json',
        body: JSON.stringify({
          detail: 'Vulnerability CVE-2099-99999 not found in any upstream intelligence source.',
          errors: ['No record found in NVD, CISA KEV, or EPSS.'],
        }),
      });
    });

    await page.goto('/');
    await page.locator('#cve-input').fill('CVE-2099-99999');
    await page.locator('#btn-analyze').click();

    // Verify empty state with 404 detail
    await expect(page.locator('#state-empty')).toBeVisible();
    await expect(page.locator('#state-empty')).toContainText('not found in any upstream intelligence source');
  });

  test('should gracefully handle backend offline, show error without silent fixture substitution, and allow explicit demo fixture loading', async ({ page }) => {
    // Abort all API network requests to simulate backend connection failure
    await page.route('**/api/vulnerabilities/*', (route) => route.abort('connectionrefused'));

    await page.goto('/');

    // 1. Initial page load should explicitly indicate Ready to Analyze across header and page
    await expect(page.locator('#demo-mode-indicator')).toContainText('Ready to Analyze');
    await expect(page.locator('#pipeline-mode-badge')).toContainText('Ready to Analyze');

    // 2. Querying a non-preset when backend is offline shows clear error state
    await page.locator('#cve-input').fill('CVE-2022-12345');
    await page.locator('#btn-analyze').click();

    await expect(page.locator('#state-error')).toBeVisible();
    await expect(page.locator('#state-error')).toContainText('Backend API service is offline or unreachable');

    // 3. Clicking a preset pill when backend is offline also attempts live analysis, fails, and DOES NOT silently render fixture
    await page.locator('button[data-cve="CVE-2024-21413"]').click();
    await expect(page.locator('#state-error')).toBeVisible();
    await expect(page.locator('#state-error')).toContainText('Backend API service is offline or unreachable');

    // 4. Explicit action allows loading the offline demo fixture
    const loadFixtureBtn = page.locator('#btn-load-offline-fixture');
    await expect(loadFixtureBtn).toBeVisible();
    await loadFixtureBtn.click();

    // 5. Offline fixture loaded: header, badge, and disclaimer all agree on Offline Demo
    await expect(page.locator('#state-loaded')).toBeVisible();
    await expect(page.locator('#target-cve-id')).toContainText('CVE-2024-21413');
    await expect(page.locator('#demo-mode-indicator')).toContainText('Offline Demo');
    await expect(page.locator('#pipeline-mode-badge')).toContainText('Offline Demo Mode');
    await expect(page.locator('#data-source-disclaimer')).toContainText('Offline demo fixture');
  });

  test('should keep header and analysis view mode in sync without contradiction', async ({ page }) => {
    // Mock successful live response for preset pill
    await page.route('**/api/vulnerabilities/CVE-2024-21413**', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          cve_id: 'CVE-2024-21413',
          status: 'OK',
          retrieved_at: '2026-10-16T12:00:00Z',
          normalized: {
            title: 'MonikerLink Outlook Remote Code Execution',
            description: 'Microsoft Outlook Remote Code Execution Vulnerability.',
            primary_severity: 'CRITICAL',
            cvss_score: 9.8,
            cvss_version: '3.1',
            cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            is_cisa_kev: true,
            cisa_required_action: 'Apply vendor update.',
            cisa_due_date: '2024-03-05',
            epss_probability: 0.892,
            epss_percentile: 0.985,
            affected_cpe_count: 12,
          },
          provenance: {
            nvd: { source: 'NIST NVD', status: 'AVAILABLE', weaknesses: ['CWE-20'], cpe_configurations: [] },
            cisa_kev: { source: 'CISA KEV', status: 'LISTED', is_listed: true, date_added: '2024-02-13' },
            epss: { source: 'FIRST EPSS', status: 'AVAILABLE', probability: 0.892, percentile: 0.985 },
          },
          errors: [],
        }),
      });
    });

    await page.goto('/');

    // Initial: Ready to Analyze
    await expect(page.locator('#demo-mode-indicator')).toContainText('Ready to Analyze');
    await expect(page.locator('#pipeline-mode-badge')).toContainText('Ready to Analyze');

    // Click quick-select pill: initiates live API call
    await page.locator('button[data-cve="CVE-2024-21413"]').click();

    // After live response: Live Intelligence
    await expect(page.locator('#demo-mode-indicator')).toContainText('Live Intelligence');
    await expect(page.locator('#pipeline-mode-badge')).toContainText('Live Vulnerability Intelligence Feed');
    await expect(page.locator('#target-cve-id')).toContainText('CVE-2024-21413');

    // Load offline demo fixture explicitly via toolbar
    await page.locator('#btn-pill-demo-fixture').click();
    await expect(page.locator('#demo-mode-indicator')).toContainText('Offline Demo');
    await expect(page.locator('#pipeline-mode-badge')).toContainText('Offline Demo Mode');
  });
});
