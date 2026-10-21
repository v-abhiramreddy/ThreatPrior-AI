import { test, expect } from '@playwright/test';

test.describe('Home Page & Guided Product Experience (Phase 6.1)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('Section B — Hero: renders headline, description, primary/secondary CTAs, and sample CVE', async ({ page }) => {
    // 1. Headline & Description
    await expect(page.locator('h1')).toContainText('Know What to Fix First.');
    await expect(page.locator('section').first()).toContainText(
      'ThreatPrior AI combines AI-driven decision-making with real-world vulnerability intelligence'
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
  });

  test('Hero Primary CTA navigates to Vulnerability Analysis page', async ({ page }) => {
    await page.locator('#hero-primary-cta').click();
    await expect(page).toHaveURL(/.*#analyze/);
    await expect(page.locator('#nav-analyze-btn')).toHaveAttribute('aria-current', 'page');
    await expect(page.locator('#cve-search-card')).toBeVisible();
  });

  test('Hero Sample CVE pill navigates to Vulnerability Analysis with CVE-2021-44228 prefilled', async ({ page }) => {
    await page.locator('#hero-sample-cve-pill').click();
    await expect(page).toHaveURL(/.*#analyze/);
    await expect(page.locator('#target-cve-id')).toContainText('CVE-2021-44228');
    await expect(page.locator('#target-title')).toContainText('Log4Shell');
  });

  test('Section C — How It Works: renders 3-step structured guidance', async ({ page }) => {
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
    await expect(section).toContainText('Amazon Bedrock Claude Sonnet 4.6');
  });

  test('Section D — Actual Annotated Screenshots: walkthrough gallery tabs switch active view', async ({ page }) => {
    // Check initial active tab: CVE Search
    const searchTab = page.locator('#screenshot-tab-cve-search');
    await expect(searchTab).toBeVisible();
    await expect(searchTab).toHaveAttribute('aria-selected', 'true');

    // Check screenshot image rendered with valid alt text
    const img = page.locator('section img[alt*="ThreatPrior AI"]');
    await expect(img).toBeVisible();
    await expect(img).toHaveAttribute('src', '/screenshots/cve_search_input.png');

    // Switch to Priority & CVSS tab
    const priorityTab = page.locator('#screenshot-tab-priority-score');
    await priorityTab.click();
    await expect(priorityTab).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('section img[alt*="vulnerability summary"]')).toHaveAttribute(
      'src',
      '/screenshots/priority_cvss_score.png'
    );
    await expect(page.locator('text=CVSS v3.1 Severity Rating')).toBeVisible();

    // Switch to AI Engine Rationale tab
    const aiTab = page.locator('#screenshot-tab-ai-rationale');
    await aiTab.click();
    await expect(aiTab).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('text=Dual-AI Operational Provenance')).toBeVisible();
    await expect(page.locator('text=Claude Reasoning Synthesis')).toBeVisible();
  });

  test('Section E — Understand the analysis components: expandable technical details work', async ({ page }) => {
    await expect(page.locator('h2', { hasText: 'Understand the Analysis Components' })).toBeVisible();

    // Priority card learn more toggle
    const priorityCard = page.locator('#component-card-priority');
    await expect(priorityCard).toBeVisible();
    const learnMoreBtn = page.locator('#toggle-detail-priority');
    await expect(learnMoreBtn).toHaveAttribute('aria-expanded', 'false');

    // Expand
    await learnMoreBtn.click();
    await expect(learnMoreBtn).toHaveAttribute('aria-expanded', 'true');
    await expect(priorityCard).toContainText('Classes: Priority 1');

    // Collapse
    await learnMoreBtn.click();
    await expect(learnMoreBtn).toHaveAttribute('aria-expanded', 'false');
  });

  test('Section F — Intelligence Sources & AI Engines architecture section', async ({ page }) => {
    const archSection = page.locator('#architecture-section');
    await expect(archSection).toBeVisible();
    await expect(archSection.locator('h2', { hasText: 'Intelligence Sources & AI Engines' })).toBeVisible();

    // Data sources
    await expect(archSection.getByText('NIST NVD', { exact: true })).toBeVisible();
    await expect(archSection.getByText('CISA KEV', { exact: true })).toBeVisible();
    await expect(archSection.getByText('FIRST EPSS', { exact: true })).toBeVisible();

    // AI Engines
    await expect(archSection.locator('text=Stage 1: Strands Decider 2B')).toBeVisible();
    await expect(archSection.locator('text=Stage 2: Amazon Bedrock Claude Sonnet 4.6')).toBeVisible();

    // Operational transparency notice
    await expect(archSection.locator('text=Operational Transparency Guarantee')).toBeVisible();
  });

  test('Section G — Recent analysis preview: displays records and navigates to History', async ({ page }) => {
    await expect(page.locator('h2', { hasText: 'Recent Vulnerability Analyses' })).toBeVisible();

    // Check recent CVE cards
    await expect(page.locator('text=Apache Log4j2 JNDI RCE (Log4Shell)')).toBeVisible();

    // Click "View Full Analysis History" button
    await page.locator('#home-view-history-btn').click();
    await expect(page).toHaveURL(/.*#history/);
    await expect(page.locator('h1')).toContainText('Analysis History & Triage Queue');
  });

  test('Section H — Footer: branding, description, links, and limitation disclaimer', async ({ page }) => {
    const footer = page.locator('footer');
    await expect(footer).toContainText('ThreatPrior AI');
    await expect(footer).toContainText('Operational Notice');
    await expect(footer.locator('#footer-nav-home')).toBeVisible();
    await expect(footer.locator('#footer-nav-analyze')).toBeVisible();
    await expect(footer.locator('#footer-nav-history')).toBeVisible();

    // Footer link navigation to Vulnerability Analysis
    await footer.locator('#footer-nav-analyze').click();
    await expect(page).toHaveURL(/.*#analyze/);
  });

  test('Mobile responsiveness: verifies layout and navigation on small viewport without overflow', async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await expect(page.locator('h1')).toContainText('Know What to Fix First.');
    await expect(page.locator('#hero-primary-cta')).toBeVisible();
    await expect(page.locator('#nav-home-btn')).toBeVisible();
    await expect(page.locator('#nav-analyze-btn')).toBeVisible();
  });
});
