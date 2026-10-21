import { test, expect } from '@playwright/test';

test.describe('Navigation & Routing (Phase 6.2 Landing Page & Deep Links)', () => {
  test('Acceptance: opening root URL / in a fresh browser session renders Home immediately as default', async ({
    page,
  }) => {
    await page.goto('/');

    // Header brand and mode indicators
    await expect(page.locator('header')).toContainText('ThreatPrior AI');
    await expect(page.locator('#demo-mode-indicator')).toContainText('Ready to Analyze');

    // Default active navigation item is Home (aria-current="page")
    const homeNav = page.locator('#nav-home-btn');
    await expect(homeNav).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('#nav-analyze-btn')).not.toHaveAttribute('aria-current', 'page');
    await expect(page.locator('#nav-history-btn')).not.toHaveAttribute('aria-current', 'page');

    // Home page hero renders immediately
    await expect(page.locator('h1')).toContainText('Know What to Fix First.');
    await expect(page.locator('#hero-primary-cta')).toBeVisible();

    // Verify neither Vulnerability Analysis nor History table is rendered on root
    await expect(page.locator('#target-cve-id')).not.toBeVisible();
    await expect(page.locator('#history-table-card')).not.toBeVisible();
  });

  test('should navigate between Home, Vulnerability Analysis, and History tabs seamlessly', async ({ page }) => {
    await page.goto('/');

    // Navigate to Vulnerability Analysis
    await page.locator('#nav-analyze-btn').click();
    await expect(page).toHaveURL(/.*#analyze/);
    await expect(page.locator('#nav-analyze-btn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('#target-cve-id')).toBeVisible();

    // Navigate to History
    await page.locator('#nav-history-btn').click();
    await expect(page).toHaveURL(/.*#history/);
    await expect(page.locator('#nav-history-btn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('h1')).toContainText('Analysis History & Triage Queue');

    // Navigate back to Home via brand logo or Home button
    await page.locator('#brand-logo-btn').click();
    await expect(page).toHaveURL(/.*#home/);
    await expect(page.locator('#nav-home-btn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('h1')).toContainText('Know What to Fix First.');
  });

  test('should support deep linking to #analyze and #history', async ({ page }) => {
    // Deep link to #analyze
    await page.goto('/#analyze');
    await expect(page.locator('#target-cve-id')).toBeVisible();
    await expect(page.locator('#nav-analyze-btn')).toHaveAttribute('aria-current', 'page');

    // Deep link to #history
    await page.goto('/#history');
    await expect(page.locator('h1')).toContainText('Analysis History & Triage Queue');
    await expect(page.locator('#nav-history-btn')).toHaveAttribute('aria-current', 'page');
  });

  test('should support direct URL query parameter for CVE deep linking (?cve=CVE-2023-38606)', async ({ page }) => {
    await page.goto('/?cve=CVE-2023-38606');

    // Direct CVE parameter routes to analyze and preselects the requested CVE
    await expect(page.locator('#nav-analyze-btn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('#target-cve-id')).toContainText('CVE-2023-38606');
    await expect(page.locator('#target-title')).toContainText('Operation Triangulation Kernel Zero-Day');
  });

  test('should support browser back and forward navigation without page reload or loops', async ({ page }) => {
    await page.goto('/');
    await expect(page.locator('h1')).toContainText('Know What to Fix First.');

    // Step forward to #analyze
    await page.locator('#nav-analyze-btn').click();
    await expect(page.locator('#target-cve-id')).toBeVisible();

    // Step forward to #history
    await page.locator('#nav-history-btn').click();
    await expect(page.locator('h1')).toContainText('Analysis History & Triage Queue');

    // Browser back to #analyze
    await page.goBack();
    await expect(page.locator('#target-cve-id')).toBeVisible();
    await expect(page.locator('#nav-analyze-btn')).toHaveAttribute('aria-current', 'page');

    // Browser back to Home
    await page.goBack();
    await expect(page.locator('h1')).toContainText('Know What to Fix First.');
    await expect(page.locator('#nav-home-btn')).toHaveAttribute('aria-current', 'page');

    // Browser forward to #analyze
    await page.goForward();
    await expect(page.locator('#target-cve-id')).toBeVisible();
    await expect(page.locator('#nav-analyze-btn')).toHaveAttribute('aria-current', 'page');
  });

  test('should navigate from History table action directly to Vulnerability Analysis', async ({ page }) => {
    await page.goto('/#history');

    // Click "View Analysis" on the Apple WebKit CVE-2023-38606 row
    const row = page.locator('#auditTableBody tr', { hasText: 'CVE-2023-38606' });
    await expect(row).toBeVisible();
    await row.getByRole('button', { name: 'View Analysis' }).click();

    // Should switch to Analyze tab and display CVE-2023-38606
    await expect(page).toHaveURL(/.*#analyze/);
    await expect(page.locator('#target-cve-id')).toContainText('CVE-2023-38606');
    await expect(page.locator('#target-title')).toContainText('Operation Triangulation Kernel Zero-Day');
  });
});
