import React, { useState } from 'react';

interface HomeProps {
  onNavigate: (tab: 'home' | 'analyze' | 'history') => void;
  onSelectCve: (cve: string) => void;
}

interface WalkthroughItem {
  id: string;
  stage: string;
  title: string;
  description: string;
  callouts: string[];
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

  // Section 3: Primary Split Product Walkthrough Items
  const primaryWalkthrough: WalkthroughItem[] = [
    {
      id: 'cve-search-input',
      stage: 'Stage 01 · Query Ingestion',
      title: 'CVE Input & Triage Trigger',
      description:
        'Enter any standard CVE identifier to initiate an on-demand multi-source threat intelligence lookup. Operators can test benchmark vulnerabilities like Log4Shell or evaluate zero-day threats in seconds.',
      callouts: [
        'Instant validation of standard CVE-YYYY-NNNN format',
        'Automated telemetry retrieval from NVD, CISA KEV, and FIRST EPSS',
        'One-click benchmark presets for rapid capability demonstration',
      ],
      imageSrc: '/screenshots/cve_search_input.png',
      altText: 'ThreatPrior AI search input bar showing CVE identifier entry and Analyze action',
    },
    {
      id: 'priority-score-metrics',
      stage: 'Stage 02 · Severity & Risk Scoring',
      title: 'Priority Result & CVSS Metrics',
      description:
        'Combines intrinsic severity metrics with empirical exploitation probabilities. A prominent P1–P4 operational priority rating gives security teams an immediate, unambiguous triage tier.',
      callouts: [
        'Actionable priority classification from Critical (P1) down to Low (P4)',
        'CVSS v3.1 base score, attack complexity, and vector analysis',
        'Live FIRST EPSS 30-day weaponization probability & percentile',
      ],
      imageSrc: '/screenshots/priority_cvss_score.png',
      altText: 'ThreatPrior AI vulnerability summary showing CVSS 10.0, CISA KEV Listed status, and EPSS probability metrics',
    },
    {
      id: 'ai-rationale-guidance',
      stage: 'Stage 03 · Dual-AI Synthesis',
      title: 'AI Engine Status & Claude Rationale',
      description:
        'Provides natural language explanations and tailored mitigation roadmaps. Strands Decider 2B establishes the rapid priority decision, while Amazon Bedrock Claude Sonnet 4.6 articulates the threat exposure context.',
      callouts: [
        'Transparent dual-model provenance with verified engine status badges',
        'Contextual natural language rationale explaining why the vulnerability matters',
        'Concrete mitigation procedures with explicit operator verification warnings',
      ],
      imageSrc: '/screenshots/ai_engine_rationale.png',
      altText: 'ThreatPrior AI recommendation panel with Strands Decider 2B status and Claude Sonnet 4.6 natural language rationale',
    },
  ];

  // Section 3: Additional Split Walkthrough Items (in expandable section)
  const additionalWalkthrough: WalkthroughItem[] = [
    {
      id: 'threat-dossier',
      stage: 'Stage 04 · Authoritative Telemetry',
      title: 'Threat Intelligence Dossier',
      description:
        'Auditable deep-dive telemetry organized into collapsible accordions. Security analysts can inspect raw NIST NVD records, CISA KEV publication dates, and binding federal remediation deadlines under BOD 22-01.',
      callouts: [
        'Official CISA KEV exploitation confirmation and mandatory patch due dates',
        'Complete Common Platform Enumeration (CPE) configurations and affected versions',
        'Raw JSON telemetry available for SOC audit trails and compliance reviews',
      ],
      imageSrc: '/screenshots/threat_intelligence_sources.png',
      altText: 'Collapsible threat intelligence accordions showing NVD record telemetry, CISA KEV dates, and EPSS score details',
    },
    {
      id: 'risk-validation',
      stage: 'Stage 05 · Policy Guardrails',
      title: 'Risk Validation & Policy Safeguards',
      description:
        'Deterministic security guardrails cross-examine AI recommendations against empirical evidence. If a model attempts to under-prioritize an actively weaponized flaw, an independent safety rule triggers a policy disagreement alert.',
      callouts: [
        'Deterministic policy verification independent of generative AI weights',
        'Automatic detection of under-prioritization on actively exploited vulnerabilities',
        'Explicit evidence limitation notices surfacing missing or unverified upstream data',
      ],
      imageSrc: '/screenshots/risk_validation_limitations.png',
      altText: 'Risk validation panel displaying policy agreement status, factual risk factors, and evidence limitations',
    },
    {
      id: 'analysis-history',
      stage: 'Stage 06 · Operational Audit Queue',
      title: 'Analysis History & Triage Queue',
      description:
        'A centralized triage queue cataloging all processed CVE assessments. Security leads can monitor active mitigation statuses, filter records by severity or weaponization risk, and export compliance reports.',
      callouts: [
        'Real-time search, priority filtering, and CISA KEV status toggles',
        'One-click CSV export with complete score provenance and timestamps',
        'Instant navigation back to full deep-dive analysis for any logged record',
      ],
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
      <section className="relative px-margin py-10 md:py-14 border-b border-surface-container-high/50 bg-radial-[at_top_center] from-surface-container-low/60 via-background to-background">
        <div className="max-w-4xl mx-auto flex flex-col items-center text-center space-y-4 md:space-y-5">
          {/* Platform category badge */}
          <div className="inline-flex items-center gap-space-xs px-space-md py-1 rounded-full bg-surface-container-high/80 border border-primary/30 text-primary font-code-sm text-code-sm">
            <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
            <span className="uppercase tracking-wider font-semibold">AI-Powered Vulnerability Prioritization</span>
          </div>

          {/* Headline */}
          <h1 className="font-display text-4xl sm:text-5xl md:text-6xl font-extrabold tracking-tight text-on-surface leading-tight">
            Know What to Fix First.
          </h1>

          {/* Short product description — strictly concise on desktop */}
          <p className="font-body-lg text-body-lg text-on-surface-variant max-w-2xl leading-relaxed">
            ThreatPrior AI combines fast AI decision-making with real-world vulnerability intelligence to help security
            teams prioritize vulnerabilities and understand why they matter.
          </p>

          {/* Primary and Secondary CTAs with standardized heights */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-space-md pt-2 w-full max-w-md sm:max-w-none">
            <button
              id="hero-primary-cta"
              type="button"
              onClick={() => onNavigate('analyze')}
              className="w-full sm:w-auto h-12 inline-flex items-center justify-center gap-space-xs px-6 rounded-lg bg-primary text-on-primary font-headline-sm text-headline-sm font-semibold hover:bg-primary/90 shadow-lg shadow-primary/20 transition-all active:scale-[0.99] cursor-pointer focus-visible:ring-2 focus-visible:ring-primary focus-visible:outline-none"
            >
              <span className="material-symbols-outlined text-[20px]">bolt</span>
              <span>Start Vulnerability Analysis</span>
            </button>

            <button
              id="hero-secondary-cta"
              type="button"
              onClick={handleSmoothScrollToHowItWorks}
              className="w-full sm:w-auto h-12 inline-flex items-center justify-center gap-space-xs px-6 rounded-lg bg-surface-container-high text-on-surface hover:bg-surface-container-highest border border-surface-container-highest font-body-md text-body-md font-medium transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-primary focus-visible:outline-none"
            >
              <span className="material-symbols-outlined text-[20px] text-secondary">explore</span>
              <span>Explore How It Works</span>
            </button>
          </div>

          {/* Grounded Sample CVE Pill (Log4Shell) */}
          <div className="pt-3 w-full max-w-2xl">
            <div
              id="hero-sample-cve-pill"
              onClick={() => handleSampleCveClick('CVE-2021-44228')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && handleSampleCveClick('CVE-2021-44228')}
              className="group p-3 sm:p-4 rounded-xl bg-surface-container-low hover:bg-surface-container border border-surface-container-high hover:border-primary/40 transition-all cursor-pointer flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-left shadow-sm focus-visible:ring-2 focus-visible:ring-primary focus-visible:outline-none"
              title="Click to prefill Log4Shell in Vulnerability Analysis"
            >
              <div className="flex items-center gap-3 min-w-0">
                <div className="w-10 h-10 rounded-lg bg-error/10 border border-error/30 flex items-center justify-center text-error font-code-sm font-bold shrink-0">
                  P1
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-code-md text-code-md text-primary font-semibold whitespace-nowrap">
                      CVE-2021-44228
                    </span>
                    <span className="text-on-surface font-semibold text-body-sm whitespace-nowrap">
                      Log4Shell RCE
                    </span>
                    <span className="px-1.5 py-0.5 rounded text-[11px] font-code-sm font-semibold bg-error/20 text-error border border-error/30 whitespace-nowrap">
                      CVSS 10.0
                    </span>
                    <span className="px-1.5 py-0.5 rounded text-[11px] font-code-sm font-semibold bg-secondary/10 text-secondary border border-secondary/30 whitespace-nowrap">
                      EPSS 97.4%
                    </span>
                    <span className="px-1.5 py-0.5 rounded text-[11px] font-code-sm font-semibold bg-surface-container-highest text-on-surface-variant border border-outline-variant/30 whitespace-nowrap hidden md:inline">
                      CISA KEV Listed
                    </span>
                  </div>
                  <p className="text-on-surface-variant font-code-sm text-[12px] pt-1">
                    Sample Benchmark · CISA KEV Listed · Click to prefill in Vulnerability Analysis
                  </p>
                </div>
              </div>

              <div className="inline-flex items-center gap-1 text-primary font-code-sm text-code-sm font-medium group-hover:translate-x-0.5 transition-transform shrink-0 self-end sm:self-center">
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
      <section id="how-it-works" className="px-margin py-12 md:py-14 max-w-6xl mx-auto space-y-space-lg">
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
          <div className="p-6 rounded-xl bg-surface-container-low border border-surface-container-high flex flex-col justify-between space-y-4 group hover:border-primary/40 transition-colors">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-code-lg text-code-lg font-bold text-primary">01</span>
                <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-high text-on-surface-variant border border-surface-container-highest">
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
            <div className="pt-2 text-on-surface-variant font-code-sm text-[12px] flex items-center gap-1 border-t border-surface-container-high/40">
              <span className="material-symbols-outlined text-primary text-[16px]">verified</span>
              <span>Gathers NVD, KEV, and EPSS records</span>
            </div>
          </div>

          {/* Step 2 */}
          <div className="p-6 rounded-xl bg-surface-container-low border border-surface-container-high flex flex-col justify-between space-y-4 group hover:border-secondary/40 transition-colors">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-code-lg text-code-lg font-bold text-secondary">02</span>
                <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-high text-on-surface-variant border border-surface-container-highest">
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
            <div className="pt-2 text-on-surface-variant font-code-sm text-[12px] flex items-center gap-1 border-t border-surface-container-high/40">
              <span className="material-symbols-outlined text-secondary text-[16px]">bolt</span>
              <span>Strands Decider 2B priority decision</span>
            </div>
          </div>

          {/* Step 3 */}
          <div className="p-6 rounded-xl bg-surface-container-low border border-surface-container-high flex flex-col justify-between space-y-4 group hover:border-tertiary-container/40 transition-colors">
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-code-lg text-code-lg font-bold text-tertiary-container">03</span>
                <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-high text-on-surface-variant border border-surface-container-highest">
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
            <div className="pt-2 text-on-surface-variant font-code-sm text-[12px] flex items-center gap-1 border-t border-surface-container-high/40">
              <span className="material-symbols-outlined text-tertiary-container text-[16px]">neurology</span>
              <span>Claude Sonnet 4.6 rationale &amp; next steps</span>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 3 — SEE THREATPRIOR AI IN ACTION (SPLIT PRODUCT WALKTHROUGH)
         ========================================================================= */}
      <section id="platform-preview-section" className="px-margin py-14 md:py-16 bg-surface-container-lowest/70 border-y border-surface-container-high/50">
        <div className="max-w-6xl mx-auto space-y-space-lg md:space-y-10">
          <div className="text-center space-y-space-xs max-w-2xl mx-auto">
            <div className="inline-flex items-center gap-1 text-primary font-code-sm text-code-sm uppercase tracking-wider font-semibold">
              <span className="material-symbols-outlined text-[16px]">visibility</span>
              <span>Platform Walkthrough</span>
            </div>
            <h2 className="font-headline-lg text-headline-lg font-bold text-on-surface tracking-tight">
              See ThreatPrior AI in Action
            </h2>
            <p className="font-body-md text-body-md text-on-surface-variant">
              Explore the end-to-end vulnerability triage journey through genuine interface captures.
            </p>
          </div>

          {/* Primary Split Walkthrough Items */}
          <div className="space-y-space-md md:space-y-6">
            {primaryWalkthrough.map((item, index) => {
              const isReversed = index % 2 === 1;
              return (
                <div
                  key={item.id}
                  id={`preview-card-${item.id}`}
                  className={`rounded-2xl bg-surface-container-low border border-surface-container-high/80 overflow-hidden shadow-lg p-5 sm:p-6 lg:p-8 flex flex-col ${
                    isReversed ? 'lg:flex-row-reverse' : 'lg:flex-row'
                  } items-center gap-6 lg:gap-10 hover:border-primary/40 transition-colors`}
                >
                  {/* Screenshot Column (~55% on desktop) */}
                  <div className="w-full lg:w-[56%] shrink-0">
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
                      className="group relative w-full rounded-xl overflow-hidden border border-surface-container-high bg-surface-container-lowest/80 shadow-md cursor-pointer focus-visible:ring-2 focus-visible:ring-primary focus-visible:outline-none"
                    >
                      <img
                        src={item.imageSrc}
                        alt={item.altText}
                        className="w-full h-auto block object-contain rounded-xl group-hover:scale-[1.01] transition-transform duration-200"
                      />
                      <div className="absolute inset-0 bg-background/40 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity">
                        <span className="px-3 py-1.5 rounded-lg bg-surface-container-highest/95 text-primary font-code-sm text-[12px] font-semibold flex items-center gap-1.5 shadow-lg border border-primary/30">
                          <span className="material-symbols-outlined text-[18px]">zoom_in</span>
                          <span>Click to enlarge</span>
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Explanation Column (~45% on desktop) */}
                  <div className="w-full lg:w-[44%] flex flex-col justify-center space-y-3.5">
                    <div className="flex items-center gap-2">
                      <span className="px-2.5 py-0.5 rounded-full bg-primary/10 border border-primary/30 text-primary font-code-sm text-[11px] font-bold tracking-wider uppercase">
                        {item.stage}
                      </span>
                    </div>

                    <h3 className="font-headline-sm text-xl md:text-2xl font-bold text-on-surface tracking-tight">
                      {item.title}
                    </h3>

                    <p className="font-body-md text-body-md text-on-surface-variant leading-relaxed">
                      {item.description}
                    </p>

                    <ul className="space-y-2 pt-2 border-t border-surface-container-high/60">
                      {item.callouts.map((callout, idx) => (
                        <li key={idx} className="flex items-start gap-2 text-body-sm text-on-surface/90 font-medium">
                          <span className="material-symbols-outlined text-secondary text-[18px] shrink-0 mt-0.5">
                            check_circle
                          </span>
                          <span className="leading-snug">{callout}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Expandable Secondary Gallery: "Explore all components" */}
          <div className="pt-2 flex flex-col items-center">
            <button
              id="toggle-all-components-btn"
              type="button"
              aria-expanded={showAllComponents}
              onClick={() => setShowAllComponents(!showAllComponents)}
              className="inline-flex items-center gap-space-xs px-space-md py-2.5 rounded-lg bg-surface-container-high hover:bg-surface-container-highest text-primary font-code-sm text-code-sm font-medium border border-surface-container-highest transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-primary focus-visible:outline-none"
            >
              <span>{showAllComponents ? 'Hide extended walkthrough' : 'Explore all components (6 stages)'}</span>
              <span className="material-symbols-outlined text-[18px]">
                {showAllComponents ? 'expand_less' : 'expand_more'}
              </span>
            </button>

            {/* Collapsed by default */}
            {showAllComponents && (
              <div
                id="additional-components-gallery"
                className="w-full space-y-space-md md:space-y-6 pt-6 transition-all"
              >
                {additionalWalkthrough.map((item, index) => {
                  const isReversed = (index + primaryWalkthrough.length) % 2 === 1;
                  return (
                    <div
                      key={item.id}
                      id={`preview-card-${item.id}`}
                      className={`rounded-2xl bg-surface-container-low border border-surface-container-high/80 overflow-hidden shadow-lg p-5 sm:p-6 lg:p-8 flex flex-col ${
                        isReversed ? 'lg:flex-row-reverse' : 'lg:flex-row'
                      } items-center gap-6 lg:gap-10 hover:border-secondary/40 transition-colors`}
                    >
                      {/* Screenshot Column (~55% on desktop) */}
                      <div className="w-full lg:w-[56%] shrink-0">
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
                          className="group relative w-full rounded-xl overflow-hidden border border-surface-container-high bg-surface-container-lowest/80 shadow-md cursor-pointer focus-visible:ring-2 focus-visible:ring-primary focus-visible:outline-none"
                        >
                          <img
                            src={item.imageSrc}
                            alt={item.altText}
                            className="w-full h-auto block object-contain rounded-xl group-hover:scale-[1.01] transition-transform duration-200"
                          />
                          <div className="absolute inset-0 bg-background/40 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity">
                            <span className="px-3 py-1.5 rounded-lg bg-surface-container-highest/95 text-secondary font-code-sm text-[12px] font-semibold flex items-center gap-1.5 shadow-lg border border-secondary/30">
                              <span className="material-symbols-outlined text-[18px]">zoom_in</span>
                              <span>Click to enlarge</span>
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Explanation Column (~45% on desktop) */}
                      <div className="w-full lg:w-[44%] flex flex-col justify-center space-y-3.5">
                        <div className="flex items-center gap-2">
                          <span className="px-2.5 py-0.5 rounded-full bg-secondary/10 border border-secondary/30 text-secondary font-code-sm text-[11px] font-bold tracking-wider uppercase">
                            {item.stage}
                          </span>
                        </div>

                        <h3 className="font-headline-sm text-xl md:text-2xl font-bold text-on-surface tracking-tight">
                          {item.title}
                        </h3>

                        <p className="font-body-md text-body-md text-on-surface-variant leading-relaxed">
                          {item.description}
                        </p>

                        <ul className="space-y-2 pt-2 border-t border-surface-container-high/60">
                          {item.callouts.map((callout, idx) => (
                            <li key={idx} className="flex items-start gap-2 text-body-sm text-on-surface/90 font-medium">
                              <span className="material-symbols-outlined text-secondary text-[18px] shrink-0 mt-0.5">
                                check_circle
                              </span>
                              <span className="leading-snug">{callout}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION 4 — INTELLIGENCE & TRUST
         ========================================================================= */}
      <section id="intelligence-trust-section" className="px-margin py-12 md:py-14 max-w-6xl mx-auto space-y-space-lg">
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
              className="p-5 rounded-xl bg-surface-container-low border border-surface-container-high space-y-2 hover:border-outline-variant transition-colors"
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
          <div className="p-5 rounded-xl bg-surface-container/60 border border-outline-variant/30 flex flex-col justify-between space-y-2">
            <div className="flex items-center gap-space-xs text-amber-400 font-code-sm text-code-sm font-semibold">
              <span className="material-symbols-outlined text-[18px]">info</span>
              <span>Transparency Notice</span>
            </div>
            <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">
              Results depend on available evidence and model responses. Missing or stale source data may limit an assessment. Automated triage assists but does not replace security review.
            </p>
            <div className="pt-1 text-[11px] font-code-sm text-outline border-t border-surface-container-high/40">
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
            className="inline-flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-surface-container-low hover:bg-surface-container text-on-surface-variant hover:text-on-surface font-code-sm text-code-sm border border-surface-container-high transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-primary focus-visible:outline-none"
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
      <section id="final-cta-section" className="px-margin py-12 md:py-14 bg-surface-container-lowest/80 border-t border-surface-container-high/50">
        <div className="max-w-3xl mx-auto rounded-2xl bg-surface-container-low border border-surface-container-high p-6 md:p-10 text-center space-y-4 shadow-lg">
          <div className="w-12 h-12 rounded-xl bg-primary/10 border border-primary/30 flex items-center justify-center text-primary mx-auto">
            <span className="material-symbols-outlined text-[28px]">search_check</span>
          </div>

          <div className="space-y-2">
            <h2 className="font-headline-lg text-headline-lg font-bold text-on-surface tracking-tight">
              Ready to investigate a vulnerability?
            </h2>
            <p className="font-body-md text-body-md text-on-surface-variant max-w-xl mx-auto leading-relaxed">
              Enter any CVE to assess real-world exploitation risk, review authoritative threat telemetry, and generate
              actionable remediation steps.
            </p>
          </div>

          <div className="pt-2">
            <button
              id="final-start-btn"
              type="button"
              onClick={() => onNavigate('analyze')}
              className="h-12 inline-flex items-center justify-center gap-space-xs px-8 rounded-lg bg-primary text-on-primary font-headline-sm text-headline-sm font-semibold hover:bg-primary/90 shadow-md shadow-primary/20 transition-all active:scale-[0.99] cursor-pointer focus-visible:ring-2 focus-visible:ring-primary focus-visible:outline-none"
            >
              <span className="material-symbols-outlined text-[20px]">bolt</span>
              <span>Start Vulnerability Analysis</span>
            </button>
          </div>
        </div>
      </section>

      {/* Accessible Screenshot Preview Modal Lightbox */}
      {modalImage && (
        <div
          id="screenshot-modal"
          role="dialog"
          aria-modal="true"
          aria-label={modalImage.title}
          onClick={() => setModalImage(null)}
          className="fixed inset-0 z-50 bg-background/85 backdrop-blur-md flex items-center justify-center p-4 sm:p-6"
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
                className="text-on-surface-variant hover:text-on-surface p-1.5 rounded-lg hover:bg-surface-container-highest transition-colors cursor-pointer focus-visible:ring-2 focus-visible:ring-primary focus-visible:outline-none"
              >
                <span className="material-symbols-outlined text-[22px]">close</span>
              </button>
            </div>

            {/* Modal Image Body */}
            <div className="p-3 sm:p-5 overflow-auto flex items-center justify-center bg-surface-container-lowest">
              <img
                src={modalImage.src}
                alt={modalImage.alt}
                className="max-h-[78vh] w-auto max-w-full object-contain rounded-lg border border-surface-container-high/40 shadow-inner"
              />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
