import { test, expect } from '@playwright/test';

test.describe('Navigation & Routing', () => {
  test('should load the Home page by default', async ({ page }) => {
    await page.goto('/');

    // Header brand and mode indicators
    await expect(page.locator('header')).toContainText('ThreatPrior AI');
    await expect(page.locator('#demo-mode-indicator')).toContainText('Ready to Analyze');

    // Default active navigation item is Home
    const homeNav = page.locator('#nav-home-btn');
    await expect(homeNav).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('h1')).toContainText('Know What to Fix First.');
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

  test('should support deep linking to #analyze', async ({ page }) => {
    await page.goto('/#analyze');
    await expect(page.locator('#target-cve-id')).toBeVisible();
    await expect(page.locator('#nav-analyze-btn')).toHaveAttribute('aria-current', 'page');
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
