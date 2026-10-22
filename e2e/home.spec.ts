import { test, expect } from '@playwright/test';

test.describe('Home Page Refinement & Information Simplification (Phase 6.2)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('Section 1 — Hero: renders headline, concise description, primary/secondary CTAs, and sample CVE', async ({
    page,
  }) => {
    // 1. Headline & Description
    await expect(page.locator('h1')).toContainText('Know What to Fix First.');
    await expect(page.locator('section').first()).toContainText(
      'ThreatPrior AI combines fast AI decision-making with real-world vulnerability intelligence'
    );

    // 2. Primary & Secondary CTAs
    const primaryCta = page.locator('#hero-primary-cta');
    await expect(primaryCta).toBeVisible();
    await expect(primaryCta).toContainText('Start Vulnerability Analysis');

    const secondaryCta = page.locator('#hero-secondary-cta');
    await expect(secondaryCta).toBeVisible();
    await expect(secondaryCta).toContainText('Explore How It Works');

    // 3. Sample CVE card (Log4Shell)
    const sampleCve = page.locator('#hero-sample-cve-pill');
    await expect(sampleCve).toBeVisible();
    await expect(sampleCve).toContainText('CVE-2021-44228');
    await expect(sampleCve).toContainText('Log4Shell RCE');
    await expect(sampleCve).toContainText('CVSS 10.0');
    await expect(sampleCve).toContainText('EPSS 97.4%');
    await expect(sampleCve).toContainText('Sample Benchmark');
  });

  test('Hero Primary CTA navigates to Vulnerability Analysis page', async ({ page }) => {
    await page.locator('#hero-primary-cta').click();
    await expect(page).toHaveURL(/.*#analyze/);
    await expect(page.locator('#nav-analyze-btn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('#cve-search-card')).toBeVisible();
  });

  test('Hero Secondary CTA scrolls to How It Works section', async ({ page }) => {
    await page.locator('#hero-secondary-cta').click();
    const howItWorks = page.locator('#how-it-works');
    await expect(howItWorks).toBeInViewport();
  });

  test('Hero Sample CVE pill navigates to Vulnerability Analysis with CVE-2021-44228 prefilled without auto-analysis', async ({ page }) => {
    await page.locator('#hero-sample-cve-pill').click();
    await expect(page).toHaveURL(/.*#analyze/);
    await expect(page.locator('#cve-input')).toHaveValue('CVE-2021-44228');
    await expect(page.locator('#target-cve-id')).not.toBeVisible();
    await expect(page.locator('#state-empty')).toBeVisible();
    await expect(page.locator('#state-empty')).toContainText('Enter a CVE ID and select Analyze Vulnerability to begin.');
  });

  test('Section 2 — How It Works: renders 3-step structured guidance without jargon', async ({ page }) => {
    const section = page.locator('#how-it-works');
    await expect(section).toBeVisible();
    await expect(section.locator('h2')).toContainText('How ThreatPrior AI Works');

    // Step 1
    await expect(section).toContainText('Step 1: Enter a CVE');
    await expect(section).toContainText('CVE-2021-44228');

    // Step 2
    await expect(section).toContainText('Step 2: Evaluate vulnerability priority');
    await expect(section).toContainText('Strands Decider 2B');

    // Step 3
    await expect(section).toContainText('Step 3: Understand the assessment');
    await expect(section).toContainText('Claude Sonnet 4.6');
  });

  test('Section 3 — Platform Preview: 3 primary screenshots render, modal view opens, and expandable gallery toggles', async ({
    page,
  }) => {
    // 3 Primary screenshot cards
    const card1 = page.locator('#preview-card-cve-search-input');
    const card2 = page.locator('#preview-card-priority-score-metrics');
    const card3 = page.locator('#preview-card-ai-rationale-guidance');

    await expect(card1).toBeVisible();
    await expect(card2).toBeVisible();
    await expect(card3).toBeVisible();

    // Check images render with genuine source paths
    await expect(card1.locator('img')).toHaveAttribute('src', '/screenshots/cve_search_input.png');
    await expect(card2.locator('img')).toHaveAttribute('src', '/screenshots/priority_cvss_score.png');
    await expect(card3.locator('img')).toHaveAttribute('src', '/screenshots/ai_engine_rationale.png');

    // Test accessible modal enlargement
    await card1.locator('[role="button"]').first().click();
    const modal = page.locator('#screenshot-modal');
    await expect(modal).toBeVisible();
    await expect(modal).toHaveAttribute('role', 'dialog');
    await expect(page.locator('#close-screenshot-modal-btn')).toBeVisible();

    // Close modal
    await page.locator('#close-screenshot-modal-btn').click();
    await expect(modal).not.toBeVisible();

    // Test secondary expandable gallery ("Explore all components")
    const toggleBtn = page.locator('#toggle-all-components-btn');
    await expect(toggleBtn).toBeVisible();
    await expect(toggleBtn).toHaveAttribute('aria-expanded', 'false');
    await expect(page.locator('#additional-components-gallery')).not.toBeVisible();

    // Expand
    await toggleBtn.click();
    await expect(toggleBtn).toHaveAttribute('aria-expanded', 'true');
    const additionalGallery = page.locator('#additional-components-gallery');
    await expect(additionalGallery).toBeVisible();
    await expect(page.locator('#preview-card-threat-dossier')).toBeVisible();
    await expect(page.locator('#preview-card-risk-validation')).toBeVisible();
    await expect(page.locator('#preview-card-analysis-history')).toBeVisible();

    // Collapse
    await toggleBtn.click();
    await expect(toggleBtn).toHaveAttribute('aria-expanded', 'false');
    await expect(additionalGallery).not.toBeVisible();
  });

  test('Section 4 — Intelligence & Trust: renders 5 core components, transparency notice, and expandable glossary', async ({
    page,
  }) => {
    const section = page.locator('#intelligence-trust-section');
    await expect(section).toBeVisible();
    await expect(section.locator('h2')).toContainText('Evidence-led. AI-assisted. Transparent.');

    // 5 Core components
    await expect(page.locator('#core-comp-nvd')).toBeVisible();
    await expect(page.locator('#core-comp-cisa-kev')).toBeVisible();
    await expect(page.locator('#core-comp-epss')).toBeVisible();
    await expect(page.locator('#core-comp-strands')).toBeVisible();
    await expect(page.locator('#core-comp-claude')).toBeVisible();

    // Transparency notice
    await expect(section).toContainText('Results depend on available evidence and model responses.');

    // Expandable glossary (collapsed by default)
    const glossaryToggle = page.locator('#toggle-glossary-btn');
    await expect(glossaryToggle).toBeVisible();
    await expect(glossaryToggle).toHaveAttribute('aria-expanded', 'false');
    await expect(page.locator('#component-glossary-section')).not.toBeVisible();

    // Expand glossary
    await glossaryToggle.click();
    await expect(glossaryToggle).toHaveAttribute('aria-expanded', 'true');
    const glossary = page.locator('#component-glossary-section');
    await expect(glossary).toBeVisible();
    await expect(page.locator('#component-card-priority')).toBeVisible();
    await expect(page.locator('#component-card-cvss')).toBeVisible();
    await expect(page.locator('#component-card-epss')).toBeVisible();

    // Collapse glossary
    await glossaryToggle.click();
    await expect(glossaryToggle).toHaveAttribute('aria-expanded', 'false');
    await expect(glossary).not.toBeVisible();
  });

  test('Section 5 — Final CTA: presents clear call-to-action without mock history, and navigates to Vulnerability Analysis', async ({
    page,
  }) => {
    const finalCta = page.locator('#final-cta-section');
    await expect(finalCta).toBeVisible();
    await expect(finalCta.locator('h2')).toContainText('Ready to investigate a vulnerability?');

    // Confirm that mock history is not displayed on Home
    await expect(page.locator('text=Recent Vulnerability Analyses')).not.toBeVisible();

    // Primary button navigates to analysis
    const startBtn = page.locator('#final-start-btn');
    await expect(startBtn).toBeVisible();
    await startBtn.click();
    await expect(page).toHaveURL(/.*#analyze/);
    await expect(page.locator('#cve-search-card')).toBeVisible();
  });

  test('Footer: renders branding, compact description, direct navigation links, and operational notice', async ({
    page,
  }) => {
    const footer = page.locator('footer');
    await expect(footer).toContainText('ThreatPrior AI');
    await expect(footer).toContainText('Operational Notice');
    await expect(footer.locator('#footer-nav-home')).toBeVisible();
    await expect(footer.locator('#footer-nav-analyze')).toBeVisible();
    await expect(footer.locator('#footer-nav-history')).toBeVisible();

    // Navigate to Analysis History
    await footer.locator('#footer-nav-history').click();
    await expect(page).toHaveURL(/.*#history/);
    await expect(page.locator('h1')).toContainText('Analysis History & Triage Queue');
  });

  test('Responsive behavior: verifies layout integrity and no horizontal overflow across mobile, tablet, and desktop', async ({
    page,
  }) => {
    const viewports = [
      { width: 375, height: 667 }, // Mobile
      { width: 768, height: 1024 }, // Tablet
      { width: 1440, height: 900 }, // Desktop
    ];

    for (const vp of viewports) {
      await page.setViewportSize(vp);
      await expect(page.locator('h1')).toContainText('Know What to Fix First.');
      await expect(page.locator('#hero-primary-cta')).toBeVisible();

      // Check that page does not exhibit horizontal scrolling overflow
      const hasHorizontalScroll = await page.evaluate(() => {
        return document.documentElement.scrollWidth > document.documentElement.clientWidth;
      });
      expect(hasHorizontalScroll).toBe(false);
    }
  });
});
