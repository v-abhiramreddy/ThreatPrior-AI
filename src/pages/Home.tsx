import React, { useState } from 'react';

interface HomeProps {
  onNavigate: (tab: 'home' | 'analyze' | 'history') => void;
  onSelectCve: (cve: string) => void;
}

interface PrimaryScreenshot {
  id: string;
  title: string;
  description: string;
  imageSrc: string;
  altText: string;
}

interface AdditionalScreenshot {
  id: string;
  title: string;
  description: string;
  imageSrc: string;
  altText: string;
}

interface GlossaryItem {
  id: string;
  title: string;
  badge: string;
  badgeColor: string;
  summary: string;
  detail: string;
}

export const Home: React.FC<HomeProps> = ({ onNavigate, onSelectCve }) => {
  // State for secondary expandable screenshots
  const [showAllComponents, setShowAllComponents] = useState<boolean>(false);

  // State for optional expandable technical glossary
  const [showGlossary, setShowGlossary] = useState<boolean>(false);

  // State for accessible screenshot modal
  const [modalImage, setModalImage] = useState<{ src: string; alt: string; title: string } | null>(null);

  // Close modal on Escape key
  React.useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setModalImage(null);
      }
    };
    if (modalImage) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [modalImage]);

  const handleSmoothScrollToHowItWorks = () => {
    const el = document.getElementById('how-it-works');
    if (el) {
      el.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleSampleCveClick = (cve: string) => {
    onSelectCve(cve);
    onNavigate('analyze');
  };

  // Section 3: Primary 3 screenshots
  const primaryScreenshots: PrimaryScreenshot[] = [
    {
      id: 'cve-search-input',
      title: '1. Enter and Validate Any CVE',
      description: 'Search standard CVE identifiers to automatically query NVD, CISA KEV, and EPSS threat intelligence.',
      imageSrc: '/screenshots/cve_search_input.png',
      altText: 'ThreatPrior AI search input bar showing CVE identifier entry and Analyze action',
    },
    {
      id: 'priority-score-metrics',
      title: '2. Priority Decision and Risk Signals',
      description: 'View the assigned priority rating alongside CVSS base severity, CISA KEV status, and EPSS likelihood.',
      imageSrc: '/screenshots/priority_cvss_score.png',
      altText: 'ThreatPrior AI vulnerability summary showing CVSS 10.0, CISA KEV Listed status, and EPSS probability metrics',
    },
    {
      id: 'ai-rationale-guidance',
      title: '3. AI Rationale and Actionable Guidance',
      description: 'Read plain-English reasoning from Claude Sonnet 4.6 with tailored, step-by-step remediation procedures.',
      imageSrc: '/screenshots/ai_engine_rationale.png',
      altText: 'ThreatPrior AI recommendation panel with Strands Decider 2B status and Claude Sonnet 4.6 natural language rationale',
    },
  ];

  // Section 3: Additional 3 screenshots (in expandable section)
  const additionalScreenshots: AdditionalScreenshot[] = [
    {
      id: 'threat-dossier',
      title: 'Auditable Evidence Dossier',
      description: 'Examine raw upstream telemetry, affected software CPEs, and binding federal directive deadlines.',
      imageSrc: '/screenshots/threat_intelligence_sources.png',
      altText: 'Collapsible threat intelligence accordions showing NVD record telemetry, CISA KEV dates, and EPSS score details',
    },
    {
      id: 'risk-validation',
      title: 'Risk Policy Validation',
      description: 'Deterministic security rules cross-examine AI model outputs to catch under-prioritization.',
      imageSrc: '/screenshots/risk_validation_limitations.png',
      altText: 'Risk validation panel displaying policy agreement status, factual risk factors, and evidence limitations',
    },
    {
      id: 'analysis-history',
      title: 'Analysis History and Triage Queue',
      description: 'Search past investigations, filter by priority or active threat status, and export audit trails to CSV.',
      imageSrc: '/screenshots/analysis_history_preview.png',
      altText: 'ThreatPrior AI Analysis History table with CVE records, priority badges, CVSS scores, and export controls',
    },
  ];

  // Section 4: 5 Main Components
  const coreIntelligenceComponents = [
    {
      id: 'nvd',
      name: 'NVD',
      label: 'National Vulnerability Database',
      description: 'Vulnerability descriptions, CVSS v3.1 severity scores, and affected software CPE configurations.',
      badgeColor: 'text-primary border-primary/30 bg-primary/10',
    },
    {
      id: 'cisa-kev',
      name: 'CISA KEV',
      label: 'Known Exploited Vulnerabilities',
      description: 'Confirms whether a flaw is actively exploited in the wild and subject to federal remediation deadlines.',
      badgeColor: 'text-error border-error/30 bg-error/10',
    },
    {
      id: 'epss',
      name: 'FIRST EPSS',
      label: 'Exploit Prediction Scoring',
      description: 'Estimated empirical probability that a vulnerability will be exploited within the next 30 days.',
      badgeColor: 'text-secondary border-secondary/30 bg-secondary/10',
    },
    {
      id: 'strands',
      name: 'Strands Decider 2B',
      label: 'First-Stage Priority Decision',
      description: 'Specialized lightweight decision model that makes the initial priority determination from evidence.',
      badgeColor: 'text-secondary border-secondary/30 bg-secondary/10',
    },
    {
      id: 'claude',
      name: 'Claude Sonnet 4.6',
      label: 'Second-Stage AI Reasoning',
      description: 'Generates plain-language reasoning, exposure context, and remediation recommendations via Amazon Bedrock.',
      badgeColor: 'text-primary border-primary/30 bg-primary/10',
    },
  ];

  // Optional expandable technical glossary details
  const glossaryItems: GlossaryItem[] = [
    {
      id: 'priority',
      title: 'Priority',
      badge: 'Core Output',
      badgeColor: 'bg-primary/10 text-primary border-primary/30',
      summary: 'Actionable triage categorization (P1 Critical through P4 Low) determined by Strands Decider 2B.',
      detail:
        'Reflects operational urgency rather than theoretical risk. Critical (P1) requires immediate containment or patching within 24–48 hours, while P3/P4 flaws follow standard maintenance cycles.',
    },
    {
      id: 'cvss',
      title: 'CVSS Score & Vector',
      badge: 'Base Severity',
      badgeColor: 'bg-amber-400/10 text-amber-400 border-amber-400/30',
      summary: 'Standardized Common Vulnerability Scoring System (v3.1) base severity rating and attack specification.',
      detail:
        'Measures intrinsic severity (0.0–10.0) across attack vectors, complexity, required privileges, and impact to Confidentiality, Integrity, and Availability.',
    },
    {
      id: 'epss',
      title: 'FIRST EPSS Probability',
      badge: 'Predictive Threat',
      badgeColor: 'bg-secondary/10 text-secondary border-secondary/30',
      summary: 'FIRST.org empirical probability that a vulnerability will be actively exploited in the next 30 days.',
      detail:
        'A statistical estimate of real-world weaponization likelihood based on live attack telemetry. High EPSS scores pinpoint flaws actively targeted by adversaries.',
    },
    {
      id: 'cisa-kev',
      title: 'CISA KEV Catalog',
      badge: 'Observed Threat',
      badgeColor: 'bg-error/10 text-error border-error/30',
      summary: 'Authoritative confirmation whether a vulnerability is actively exploited by threat actors in the wild.',
      detail:
        'Listing in CISA KEV confirms verified in-the-wild exploitation or ransomware use, establishing mandatory remediation deadlines under Binding Operational Directive (BOD) 22-01.',
    },
    {
      id: 'claude-rationale',
      title: 'Claude Rationale & Remediation',
      badge: 'Stage-2 Reasoning',
      badgeColor: 'bg-primary/10 text-primary border-primary/30',
      summary: 'Amazon Bedrock Claude Sonnet 4.6 natural language explanation and defense guidance.',
      detail:
        'When Bedrock inference succeeds, Claude Sonnet 4.6 translates raw metrics into human-readable analysis and a prioritized remediation plan tailored to the affected software.',
    },
    {
      id: 'risk-validation',
      title: 'Evidence Validation Guardrail',
      badge: 'Safety Policy',
      badgeColor: 'bg-secondary/10 text-secondary border-secondary/30',
      summary: 'Deterministic policy rule comparison that cross-examines model priority against empirical evidence.',
      detail:
        'An independent ruleset verifies that actively exploited or critical-impact flaws receive high priority, raising a Policy Disagreement alert if an AI model under-prioritizes real threat evidence.',
    },
    {
      id: 'engine-status',
      title: 'Engine Status & Degradation',
      badge: 'Operational Transparency',
      badgeColor: 'bg-surface-container-high text-on-surface-variant border-outline-variant/40',
      summary: 'Truthful disclosure of whether dual-AI succeeded or the application operated in a degraded state.',
      detail:
        'Discloses exact pipeline status (dual-AI, decider-only, bedrock-only, or rule fallback) and clarifies when model confidence scores are uncalibrated.',
    },
    {
      id: 'evidence-limitations',
      title: 'Evidence Limitations',
      badge: 'Analytical Honesty',
      badgeColor: 'bg-amber-400/10 text-amber-400 border-amber-400/30',
      summary: 'Disclosures detailing missing upstream telemetry, unverified CLI commands, or source registry lag.',
      detail:
        'Surfaces transparent warnings when patch targets cannot be validated against official CPE registries or when remediation commands represent AI synthesis requiring operator verification.',
    },
  ];

  return (
    <div className="w-full bg-background text-on-surface">
      {/* =========================================================================
          SECTION 1 — HERO
         ========================================================================= */}
      <section className="relative px-margin py-12 md:py-16 border-b border-surface-container-high/50 bg-radial-[at_top_center] from-surface-container-low/60 via-background to-background">
        <div className="max-w-4xl mx-auto flex flex-col items-center text-center space-y-space-md">
          {/* Platform category badge */}
          <div className="inline-flex items-center gap-space-xs px-space-md py-1 rounded-full bg-surface-container-high/80 border border-primary/30 text-primary font-code-sm text-code-sm">
            <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
            <span className="uppercase tracking-wider font-semibold">AI-Powered Vulnerability Prioritization</span>
          </div>

          {/* Headline */}
          <h1 className="font-display text-4xl sm:text-5xl md:text-6xl font-extrabold tracking-tight text-on-surface leading-tight">
            Know What to Fix First.
          </h1>

          {/* Short product description — max two lines on desktop */}
          <p className="font-body-lg text-body-lg text-on-surface-variant max-w-2xl leading-relaxed">
            ThreatPrior AI combines fast AI decision-making with real-world vulnerability intelligence to help security
            teams prioritize vulnerabilities and understand why they matter.
          </p>

          {/* Primary and Secondary CTAs */}
          <div className="flex flex-col sm:flex-row items-center gap-space-md pt-space-xs">
            <button
              id="hero-primary-cta"
              type="button"
              onClick={() => onNavigate('analyze')}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-space-xs px-space-xl py-3 rounded-lg bg-primary text-on-primary font-headline-sm text-headline-sm font-semibold hover:bg-primary/90 shadow-lg shadow-primary/10 transition-all active:scale-[0.99] cursor-pointer"
            >
              <span className="material-symbols-outlined text-[20px]">bolt</span>
              <span>Start Vulnerability Analysis</span>
            </button>

            <button
              id="hero-secondary-cta"
              type="button"
              onClick={handleSmoothScrollToHowItWorks}
              className="w-full sm:w-auto inline-flex items-center justify-center gap-space-xs px-space-lg py-3 rounded-lg bg-surface-container-high text-on-surface hover:bg-surface-container-highest border border-surface-container-highest font-body-md text-body-md font-medium transition-colors cursor-pointer"
            >
              <span className="material-symbols-outlined text-[20px] text-secondary">explore</span>
              <span>Explore How It Works</span>
            </button>
          </div>

          {/* Grounded Sample CVE Pill (Log4Shell) */}
          <div className="pt-space-sm w-full max-w-xl">
            <div
              id="hero-sample-cve-pill"
              onClick={() => handleSampleCveClick('CVE-2021-44228')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => e.key === 'Enter' && handleSampleCveClick('CVE-2021-44228')}
              className="group p-space-sm sm:p-space-md rounded-xl bg-surface-container-low hover:bg-surface-container border border-surface-container-high hover:border-primary/40 transition-all cursor-pointer flex flex-col sm:flex-row items-start sm:items-center justify-between gap-space-xs sm:gap-space-sm text-left shadow-sm"
              title="Click to prefill Log4Shell in Vulnerability Analysis"
            >
              <div className="flex items-center gap-space-sm">
                <div className="w-9 h-9 rounded-lg bg-error/10 border border-error/30 flex items-center justify-center text-error font-code-sm font-bold shrink-0">
                  P1
                </div>
                <div>
                  <div className="flex items-center gap-space-xs flex-wrap">
                    <span className="font-code-md text-code-md text-primary font-semibold">CVE-2021-44228</span>
                    <span className="text-on-surface font-medium text-body-sm">Log4Shell RCE</span>
                    <span className="px-1.5 py-0.5 rounded text-[11px] font-code-sm font-semibold bg-error/20 text-error border border-error/30">
                      CVSS 10.0
                    </span>
                    <span className="px-1.5 py-0.5 rounded text-[11px] font-code-sm font-semibold bg-secondary/10 text-secondary border border-secondary/30">
                      EPSS 97.4%
                    </span>
                  </div>
                  <p className="text-on-surface-variant font-code-sm text-[12px] pt-0.5">
                    Sample Benchmark · CISA KEV Listed · Instant prefill available
                  </p>
                </div>
              </div>

              <div className="inline-flex items-center gap-1 text-primary font-code-sm text-code-sm font-medium group-hover:translate-x-0.5 transition-transform self-end sm:self-auto shrink-0">
                <span>Analyze Sample CVE</span>
                <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 2 — HOW IT WORKS
         ========================================================================= */}
      <section id="how-it-works" className="px-margin py-14 max-w-6xl mx-auto space-y-space-lg">
        <div className="text-center space-y-space-xs max-w-2xl mx-auto">
          <div className="inline-flex items-center gap-1 text-secondary font-code-sm text-code-sm uppercase tracking-wider font-semibold">
            <span className="material-symbols-outlined text-[16px]">schema</span>
            <span>Three-Step Workflow</span>
          </div>
          <h2 className="font-headline-lg text-headline-lg font-bold text-on-surface tracking-tight">
            How ThreatPrior AI Works
          </h2>
          <p className="font-body-md text-body-md text-on-surface-variant">
            From vulnerability identifier to actionable mitigation in three clear steps.
          </p>
        </div>

        {/* Balanced 3-column layout on desktop, stacked on mobile */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-space-md">
          {/* Step 1 */}
          <div className="p-space-lg rounded-xl bg-surface-container-low border border-surface-container-high flex flex-col justify-between space-y-space-sm group hover:border-primary/40 transition-colors">
            <div className="space-y-space-xs">
              <div className="flex items-center justify-between">
                <span className="font-code-lg text-code-lg font-bold text-primary">01</span>
                <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-high text-on-surface-variant">
                  Input
                </span>
              </div>
              <h3 className="font-headline-sm text-headline-sm font-semibold text-on-surface">
                Step 1: Enter a CVE
              </h3>
              <p className="font-body-md text-body-md text-on-surface-variant leading-relaxed">
                Enter any standard CVE identifier, such as <code className="text-primary font-code-sm">CVE-2021-44228</code>.
                The application automatically gathers verified records from NIST NVD, CISA KEV, and FIRST EPSS.
              </p>
            </div>
            <div className="pt-space-xs text-on-surface-variant font-code-sm text-[12px] flex items-center gap-1">
              <span className="material-symbols-outlined text-primary text-[16px]">verified</span>
              <span>Gathers NVD, KEV, and EPSS records</span>
            </div>
          </div>

          {/* Step 2 */}
          <div className="p-space-lg rounded-xl bg-surface-container-low border border-surface-container-high flex flex-col justify-between space-y-space-sm group hover:border-secondary/40 transition-colors">
            <div className="space-y-space-xs">
              <div className="flex items-center justify-between">
                <span className="font-code-lg text-code-lg font-bold text-secondary">02</span>
                <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-high text-on-surface-variant">
                  Decision
                </span>
              </div>
              <h3 className="font-headline-sm text-headline-sm font-semibold text-on-surface">
                Step 2: Evaluate vulnerability priority
              </h3>
              <p className="font-body-md text-body-md text-on-surface-variant leading-relaxed">
                Strands Decider 2B evaluates the gathered vulnerability evidence to assign an immediate priority tier
                from Critical (P1) down to Low (P4).
              </p>
            </div>
            <div className="pt-space-xs text-on-surface-variant font-code-sm text-[12px] flex items-center gap-1">
              <span className="material-symbols-outlined text-secondary text-[16px]">bolt</span>
              <span>Strands Decider 2B priority decision</span>
            </div>
          </div>

          {/* Step 3 */}
          <div className="p-space-lg rounded-xl bg-surface-container-low border border-surface-container-high flex flex-col justify-between space-y-space-sm group hover:border-tertiary-container/40 transition-colors">
            <div className="space-y-space-xs">
              <div className="flex items-center justify-between">
                <span className="font-code-lg text-code-lg font-bold text-tertiary-container">03</span>
                <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-high text-on-surface-variant">
                  Reasoning
                </span>
              </div>
              <h3 className="font-headline-sm text-headline-sm font-semibold text-on-surface">
                Step 3: Understand the assessment
              </h3>
              <p className="font-body-md text-body-md text-on-surface-variant leading-relaxed">
                Amazon Bedrock Claude Sonnet 4.6 explains the decision rationale, identifies exposure factors, and
                outlines actionable remediation recommendations.
              </p>
            </div>
            <div className="pt-space-xs text-on-surface-variant font-code-sm text-[12px] flex items-center gap-1">
              <span className="material-symbols-outlined text-tertiary-container text-[16px]">neurology</span>
              <span>Claude Sonnet 4.6 rationale &amp; next steps</span>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 3 — SEE THREATPRIOR AI IN ACTION
         ========================================================================= */}
      <section id="platform-preview-section" className="px-margin py-14 bg-surface-container-lowest/70 border-y border-surface-container-high/50">
        <div className="max-w-6xl mx-auto space-y-space-lg">
          <div className="text-center space-y-space-xs max-w-2xl mx-auto">
            <div className="inline-flex items-center gap-1 text-primary font-code-sm text-code-sm uppercase tracking-wider font-semibold">
              <span className="material-symbols-outlined text-[16px]">visibility</span>
              <span>Platform Preview</span>
            </div>
            <h2 className="font-headline-lg text-headline-lg font-bold text-on-surface tracking-tight">
              See ThreatPrior AI in Action
            </h2>
            <p className="font-body-md text-body-md text-on-surface-variant">
              Genuine interfaces and decision outputs captured directly from the live application.
            </p>
          </div>

          {/* 3 Primary Screenshots Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-space-md">
            {primaryScreenshots.map((item) => (
              <div
                key={item.id}
                id={`preview-card-${item.id}`}
                className="group rounded-xl bg-surface-container-low border border-surface-container-high overflow-hidden shadow-sm flex flex-col justify-between hover:border-primary/40 transition-colors"
              >
                {/* Sized naturally to fit content with subtle border and clickable for enlargement */}
                <div
                  role="button"
                  tabIndex={0}
                  aria-label={`Enlarge screenshot: ${item.title}`}
                  onClick={() => setModalImage({ src: item.imageSrc, alt: item.altText, title: item.title })}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      setModalImage({ src: item.imageSrc, alt: item.altText, title: item.title });
                    }
                  }}
                  className="relative w-full bg-surface-container-lowest border-b border-surface-container-high/60 overflow-hidden flex items-center justify-center p-2 cursor-pointer"
                >
                  <img
                    src={item.imageSrc}
                    alt={item.altText}
                    className="w-full h-auto max-h-[220px] object-contain rounded group-hover:scale-[1.01] transition-transform duration-200"
                  />
                  <div className="absolute inset-0 bg-background/30 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity">
                    <span className="px-2.5 py-1 rounded-md bg-surface-container-highest/90 text-primary font-code-sm text-[12px] flex items-center gap-1 shadow-md border border-primary/20">
                      <span className="material-symbols-outlined text-[16px]">zoom_in</span>
                      <span>Enlarge view</span>
                    </span>
                  </div>
                </div>

                <div className="p-space-md space-y-1">
                  <h3 className="font-headline-sm text-body-md font-semibold text-on-surface">
                    {item.title}
                  </h3>
                  <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">
                    {item.description}
                  </p>
                </div>
              </div>
            ))}
          </div>

          {/* Expandable Secondary Gallery: "Explore all components" */}
          <div className="pt-space-xs flex flex-col items-center">
            <button
              id="toggle-all-components-btn"
              type="button"
              aria-expanded={showAllComponents}
              onClick={() => setShowAllComponents(!showAllComponents)}
              className="inline-flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-surface-container-high hover:bg-surface-container-highest text-primary font-code-sm text-code-sm font-medium border border-surface-container-highest transition-colors cursor-pointer"
            >
              <span>{showAllComponents ? 'Hide additional views' : 'Explore all components'}</span>
              <span className="material-symbols-outlined text-[18px]">
                {showAllComponents ? 'expand_less' : 'expand_more'}
              </span>
            </button>

            {/* Collapsed by default */}
            {showAllComponents && (
              <div
                id="additional-components-gallery"
                className="grid grid-cols-1 md:grid-cols-3 gap-space-md w-full pt-space-md transition-all"
              >
                {additionalScreenshots.map((item) => (
                  <div
                    key={item.id}
                    id={`preview-card-${item.id}`}
                    className="group rounded-xl bg-surface-container-low border border-surface-container-high overflow-hidden shadow-sm flex flex-col justify-between hover:border-secondary/40 transition-colors"
                  >
                    <div
                      role="button"
                      tabIndex={0}
                      aria-label={`Enlarge screenshot: ${item.title}`}
                      onClick={() => setModalImage({ src: item.imageSrc, alt: item.altText, title: item.title })}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          setModalImage({ src: item.imageSrc, alt: item.altText, title: item.title });
                        }
                      }}
                      className="relative w-full bg-surface-container-lowest border-b border-surface-container-high/60 overflow-hidden flex items-center justify-center p-2 cursor-pointer"
                    >
                      <img
                        src={item.imageSrc}
                        alt={item.altText}
                        className="w-full h-auto max-h-[220px] object-contain rounded group-hover:scale-[1.01] transition-transform duration-200"
                      />
                      <div className="absolute inset-0 bg-background/30 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity">
                        <span className="px-2.5 py-1 rounded-md bg-surface-container-highest/90 text-secondary font-code-sm text-[12px] flex items-center gap-1 shadow-md border border-secondary/20">
                          <span className="material-symbols-outlined text-[16px]">zoom_in</span>
                          <span>Enlarge view</span>
                        </span>
                      </div>
                    </div>

                    <div className="p-space-md space-y-1">
                      <h3 className="font-headline-sm text-body-md font-semibold text-on-surface">
                        {item.title}
                      </h3>
                      <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">
                        {item.description}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 4 — INTELLIGENCE & TRUST
         ========================================================================= */}
      <section id="intelligence-trust-section" className="px-margin py-14 max-w-6xl mx-auto space-y-space-lg">
        <div className="text-center space-y-space-xs max-w-2xl mx-auto">
          <div className="inline-flex items-center gap-1 text-secondary font-code-sm text-code-sm uppercase tracking-wider font-semibold">
            <span className="material-symbols-outlined text-[16px]">verified_user</span>
            <span>Architecture &amp; Data Pipeline</span>
          </div>
          <h2 className="font-headline-lg text-headline-lg font-bold text-on-surface tracking-tight">
            Evidence-led. AI-assisted. Transparent.
          </h2>
          <p className="font-body-md text-body-md text-on-surface-variant">
            Five dedicated intelligence and AI components work together to deliver defensible vulnerability priorities.
          </p>
        </div>

        {/* 5 Core Components in a balanced responsive grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-space-md">
          {coreIntelligenceComponents.map((comp) => (
            <div
              key={comp.id}
              id={`core-comp-${comp.id}`}
              className="p-space-md rounded-xl bg-surface-container-low border border-surface-container-high space-y-space-xs hover:border-outline-variant transition-colors"
            >
              <div className="flex items-center justify-between">
                <span className="font-headline-sm text-body-md font-bold text-on-surface">
                  {comp.name}
                </span>
                <span className={`px-2 py-0.5 rounded text-[11px] font-code-sm font-semibold border ${comp.badgeColor}`}>
                  {comp.id === 'strands' || comp.id === 'claude' ? 'AI Engine' : 'Telemetry'}
                </span>
              </div>
              <div className="font-code-sm text-[12px] text-on-surface-variant font-medium">
                {comp.label}
              </div>
              <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed pt-1">
                {comp.description}
              </p>
            </div>
          ))}

          {/* Unobtrusive transparency note card occupying the 6th slot for clean 3x2 balance */}
          <div className="p-space-md rounded-xl bg-surface-container/60 border border-outline-variant/30 flex flex-col justify-between space-y-space-xs">
            <div className="flex items-center gap-space-xs text-amber-400 font-code-sm text-code-sm font-semibold">
              <span className="material-symbols-outlined text-[18px]">info</span>
              <span>Transparency Notice</span>
            </div>
            <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">
              Results depend on available evidence and model responses. Missing or stale source data may limit an assessment. Automated triage assists but does not replace security review.
            </p>
            <div className="pt-space-xs text-[11px] font-code-sm text-outline">
              Graceful fallback active when upstream services degrade.
            </div>
          </div>
        </div>

        {/* Accessible Expandable Detailed Glossary for in-depth technical inspection */}
        <div className="pt-space-xs flex flex-col items-center">
          <button
            id="toggle-glossary-btn"
            type="button"
            aria-expanded={showGlossary}
            onClick={() => setShowGlossary(!showGlossary)}
            className="inline-flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-surface-container-low hover:bg-surface-container text-on-surface-variant hover:text-on-surface font-code-sm text-code-sm border border-surface-container-high transition-colors cursor-pointer"
          >
            <span>{showGlossary ? 'Hide technical glossary' : 'View detailed technical glossary'}</span>
            <span className="material-symbols-outlined text-[18px]">
              {showGlossary ? 'expand_less' : 'expand_more'}
            </span>
          </button>

          {/* Detailed glossary collapsed by default */}
          {showGlossary && (
            <div
              id="component-glossary-section"
              className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-space-md w-full pt-space-md transition-all"
            >
              {glossaryItems.map((item) => (
                <div
                  key={item.id}
                  id={`component-card-${item.id}`}
                  className="p-space-md rounded-xl bg-surface-container-low border border-surface-container-high space-y-space-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-headline-sm text-headline-sm font-semibold text-on-surface">
                      {item.title}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[11px] font-code-sm font-semibold border ${item.badgeColor}`}>
                      {item.badge}
                    </span>
                  </div>
                  <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">
                    {item.summary}
                  </p>
                  <p className="font-body-sm text-body-sm text-on-surface/90 pt-1 border-t border-surface-container-high/60">
                    {item.detail}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      {/* =========================================================================
          SECTION 5 — FINAL CTA
         ========================================================================= */}
      <section id="final-cta-section" className="px-margin py-14 bg-surface-container-lowest/80 border-t border-surface-container-high/50">
        <div className="max-w-3xl mx-auto rounded-2xl bg-surface-container-low border border-surface-container-high p-space-lg md:p-space-xl text-center space-y-space-md shadow-lg">
          <div className="w-12 h-12 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center text-primary mx-auto">
            <span className="material-symbols-outlined text-[28px]">search_check</span>
          </div>

          <div className="space-y-space-xs">
            <h2 className="font-headline-lg text-headline-lg font-bold text-on-surface tracking-tight">
              Ready to investigate a vulnerability?
            </h2>
            <p className="font-body-md text-body-md text-on-surface-variant max-w-xl mx-auto leading-relaxed">
              Enter any CVE to assess real-world exploitation risk, review authoritative threat telemetry, and generate
              actionable remediation steps.
            </p>
          </div>

          <div className="pt-space-xs">
            <button
              id="final-start-btn"
              type="button"
              onClick={() => onNavigate('analyze')}
              className="inline-flex items-center justify-center gap-space-xs px-space-xl py-3 rounded-lg bg-primary text-on-primary font-headline-sm text-headline-sm font-semibold hover:bg-primary/90 shadow-md shadow-primary/20 transition-all active:scale-[0.99] cursor-pointer"
            >
              <span className="material-symbols-outlined text-[20px]">bolt</span>
              <span>Start Vulnerability Analysis</span>
            </button>
          </div>
        </div>
      </section>

      {/* Accessible Screenshot Preview Modal */}
      {modalImage && (
        <div
          id="screenshot-modal"
          role="dialog"
          aria-modal="true"
          aria-label={modalImage.title}
          onClick={() => setModalImage(null)}
          className="fixed inset-0 z-50 bg-background/80 backdrop-blur-md flex items-center justify-center p-4 sm:p-6"
        >
          <div
            className="relative max-w-5xl w-full max-h-[92vh] bg-surface-container-low border border-surface-container-high rounded-2xl overflow-hidden shadow-2xl flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="flex items-center justify-between px-4 sm:px-6 py-3.5 border-b border-surface-container-high bg-surface-container">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-primary text-[20px]">preview</span>
                <h4 className="font-headline-sm text-body-md font-semibold text-on-surface">
                  {modalImage.title}
                </h4>
              </div>
              <button
                id="close-screenshot-modal-btn"
                type="button"
                aria-label="Close image preview"
                onClick={() => setModalImage(null)}
                className="text-on-surface-variant hover:text-on-surface p-1 rounded-lg hover:bg-surface-container-highest transition-colors cursor-pointer"
              >
                <span className="material-symbols-outlined text-[22px]">close</span>
              </button>
            </div>

            {/* Modal Image Body */}
            <div className="p-3 sm:p-4 overflow-auto flex items-center justify-center bg-surface-container-lowest">
              <img
                src={modalImage.src}
                alt={modalImage.alt}
                className="max-h-[76vh] w-auto max-w-full object-contain rounded-lg border border-surface-container-high/40 shadow-inner"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
