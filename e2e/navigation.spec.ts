import { test, expect } from '@playwright/test';

test.describe('Navigation & Routing', () => {
  test('should load the Vulnerability Analysis page by default', async ({ page }) => {
    await page.goto('/');

    // Header brand and mode indicators
    await expect(page.locator('header')).toContainText('ThreatPrior AI');
    await expect(page.locator('#demo-mode-indicator')).toContainText('Demo Data Mode');

    // Default active navigation item
    const analyzeNav = page.locator('#nav-analyze-btn');
    await expect(analyzeNav).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('h1')).toContainText('Know what to fix first.');
  });

  test('should navigate between Analyze and History tabs seamlessly', async ({ page }) => {
    await page.goto('/');

    // Navigate to History
    await page.locator('#nav-history-btn').click();
    await expect(page).toHaveURL(/.*#history/);
    await expect(page.locator('#nav-history-btn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('h1')).toContainText('Analysis History & Triage Queue');

    // Navigate back to Analyze
    await page.locator('#nav-analyze-btn').click();
    await expect(page).toHaveURL(/.*#analyze/);
    await expect(page.locator('#nav-analyze-btn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('h1')).toContainText('Know what to fix first.');
  });

  test('should support deep linking to #history', async ({ page }) => {
    await page.goto('/#history');
    await expect(page.locator('h1')).toContainText('Analysis History & Triage Queue');
    await expect(page.locator('#nav-history-btn')).toHaveAttribute('aria-current', 'page');
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
