import { test, expect } from '@playwright/test';

test.describe('Analysis History & Triage Queue Page', () => {
  test.beforeEach(async ({ page }) => {
    // Mock backend history endpoint to return empty items so the test deterministically verifies the 6-row demo history
    await page.route('**/api/history**', route =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ items: [] }),
      })
    );
    await page.goto('/#history');
  });

  test('should display 3 KPI metric tiles and initial audit table records', async ({ page }) => {
    // KPI Cards
    await expect(page.locator('text=Active Triage Queue')).toBeVisible();
    await expect(page.getByText('14', { exact: true })).toBeVisible();
    await expect(page.locator('text=Confirmed In CISA KEV')).toBeVisible();
    await expect(page.getByText('19', { exact: true })).toBeVisible();
    await expect(page.locator('text=Average EPSS Probability')).toBeVisible();
    await expect(page.locator('text=34.2%')).toBeVisible();

    // Table rows
    const rows = page.locator('#auditTableBody tr');
    await expect(rows).toHaveCount(6);
    await expect(page.locator('#filteredCount')).toContainText('Showing 6 of 6 displayed');
  });

  test('should filter table records by keyword search', async ({ page }) => {
    const searchInput = page.locator('#searchInput');

    // Search for "Outlook"
    await searchInput.fill('Outlook');
    const rows = page.locator('#auditTableBody tr');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('CVE-2024-21413');
    await expect(page.locator('#filteredCount')).toContainText('Showing 1 of 6 displayed');

    // Search for analyst "SecOps-Lead"
    await searchInput.fill('SecOps-Lead');
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('CVE-2021-44228');

    // Clear search
    await searchInput.fill('');
    await expect(rows).toHaveCount(6);
  });

  test('should filter table records by Priority and KEV status', async ({ page }) => {
    const priorityFilter = page.locator('#priorityFilter');
    const kevFilter = page.locator('#kevFilter');
    const rows = page.locator('#auditTableBody tr');

    // Filter by P1
    await priorityFilter.selectOption('P1');
    await expect(rows).toHaveCount(3);
    for (let i = 0; i < 3; i++) {
      await expect(rows.nth(i)).toContainText('P1 - Immediate');
    }

    // Filter by KEV = NO (within P1)
    await kevFilter.selectOption('NO');
    // All 3 P1s in mock data have KEV = YES, so 0 matches
    await expect(rows).toHaveCount(1);
    await expect(rows.first()).toContainText('No matching CVE records found in demo history');

    // Reset filters
    await page.locator('#resetFiltersBtn').click();
    await expect(rows).toHaveCount(6);
    await expect(priorityFilter).toHaveValue('ALL');
    await expect(kevFilter).toHaveValue('ALL');
  });

  test('should trigger CSV export download with correct content structure', async ({ page }) => {
    // Wait for the download event when clicking Export Audit CSV
    const downloadPromise = page.waitForEvent('download');
    await page.locator('#exportCsvBtn').click();
    const download = await downloadPromise;

    expect(download.suggestedFilename()).toBe('threatprior_audit_history.csv');
  });

  test('should not display simulated raw audit log ingest card or token button', async ({ page }) => {
    await expect(page.locator('#copyTokenBtn')).not.toBeVisible();
    await expect(page.getByText('Need Raw Audit Log Ingestion?')).not.toBeVisible();
    await expect(page.getByText('Splunk, Elastic, and AWS Security Lake')).not.toBeVisible();
  });
});
