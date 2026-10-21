import { test, expect } from '@playwright/test';
import fs from 'fs';
import path from 'path';

test.describe('Visual Inspection Screenshots', () => {
  test('capture full page and component screenshots for Home page gallery', async ({ page }) => {
    // 1. Capture Vulnerability Analysis Page & Components
    await page.goto('/#analyze');
    await page.setViewportSize({ width: 1440, height: 1800 });
    await expect(page.locator('#state-loaded')).toBeVisible();

    // Full page analysis screenshot
    await page.screenshot({ path: 'screenshots/vulnerability_analysis.png', fullPage: true });

    // Component 1: CVE Input and Search Action
    const cveCard = page.locator('#cve-search-card');
    await expect(cveCard).toBeVisible();
    await cveCard.screenshot({ path: 'screenshots/cve_search_input.png' });

    // Component 2: Priority Result and CVSS Information
    const priorityCvssCard = page.locator('#priority-cvss-card');
    await expect(priorityCvssCard).toBeVisible();
    await priorityCvssCard.screenshot({ path: 'screenshots/priority_cvss_score.png' });

    // Component 3: AI Engine Status and Claude Rationale
    const aiCard = page.locator('#ai-engine-rationale-card');
    await expect(aiCard).toBeVisible();
    await aiCard.screenshot({ path: 'screenshots/ai_engine_rationale.png' });

    // Component 4: Threat Intelligence Sources (NVD, CISA KEV, EPSS)
    const dossierSection = page.locator('#evidence-dossier-section');
    await expect(dossierSection).toBeVisible();
    await dossierSection.screenshot({ path: 'screenshots/threat_intelligence_sources.png' });

    // Component 5: Risk Validation Warnings & Data-source Limitations
    const riskPanel = page.locator('#risk-validation-panel');
    await expect(riskPanel).toBeVisible();
    await riskPanel.screenshot({ path: 'screenshots/risk_validation_limitations.png' });

    // 2. Capture Analysis History Page & Component
    await page.goto('/#history');
    await page.setViewportSize({ width: 1440, height: 1200 });
    await expect(page.locator('#history-table-card')).toBeVisible();

    // Full page history screenshot
    await page.screenshot({ path: 'screenshots/analysis_history.png', fullPage: true });

    // Component 6: Analysis History Table Preview
    const historyCard = page.locator('#history-table-card');
    await historyCard.screenshot({ path: 'screenshots/analysis_history_preview.png' });

    // Copy captured screenshots to public/screenshots/ for frontend gallery consumption
    const screenshotFiles = [
      'cve_search_input.png',
      'priority_cvss_score.png',
      'ai_engine_rationale.png',
      'threat_intelligence_sources.png',
      'risk_validation_limitations.png',
      'analysis_history_preview.png',
      'vulnerability_analysis.png',
      'analysis_history.png',
    ];

    for (const file of screenshotFiles) {
      const srcPath = path.join(process.cwd(), 'screenshots', file);
      const destPath = path.join(process.cwd(), 'public', 'screenshots', file);
      if (fs.existsSync(srcPath)) {
        fs.copyFileSync(srcPath, destPath);
      }
    }
  });
});

