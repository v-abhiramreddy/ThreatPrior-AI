import { test } from '@playwright/test';

test.describe('Visual Inspection Screenshots', () => {
  test('capture full page screenshots of both screens', async ({ page }) => {
    // 1. Capture Vulnerability Analysis Page
    await page.goto('/');
    await page.setViewportSize({ width: 1440, height: 1800 });
    await page.screenshot({ path: 'screenshots/vulnerability_analysis.png', fullPage: true });

    // 2. Capture Analysis History Page
    await page.goto('/#history');
    await page.setViewportSize({ width: 1440, height: 1200 });
    await page.screenshot({ path: 'screenshots/analysis_history.png', fullPage: true });
  });
});
