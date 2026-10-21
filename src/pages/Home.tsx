import React, { useState } from 'react';
import { DEMO_AUDIT_HISTORY } from '../mockData';
import type { AuditRecord } from '../types';

interface HomeProps {
  onNavigate: (tab: 'home' | 'analyze' | 'history') => void;
  onSelectCve: (cve: string) => void;
}

interface ComponentExplanation {
  id: string;
  title: string;
  badge: string;
  badgeColor: string;
  summary: string;
  detail: string;
  technicalMetric: string;
  icon: string;
}

interface ScreenshotWalkthroughItem {
  id: string;
  title: string;
  subtitle: string;
  imageSrc: string;
  altText: string;
  description: string;
  callouts: Array<{ number: number; label: string; explanation: string }>;
}

export const Home: React.FC<HomeProps> = ({ onNavigate, onSelectCve }) => {
  // Screenshot gallery active tab state
  const [activeScreenshotTab, setActiveScreenshotTab] = useState<string>('cve-search');

  // Analysis components expandable detail states
  const [expandedComponents, setExpandedComponents] = useState<Record<string, boolean>>({});

  const toggleComponentDetail = (id: string) => {
    setExpandedComponents((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

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

  // Section D: Genuine Screenshots data
  const screenshotItems: ScreenshotWalkthroughItem[] = [
    {
      id: 'cve-search',
      title: '1. CVE Input & Triage Trigger',
      subtitle: 'Standardized query entry and rapid pipeline dispatch',
      imageSrc: '/screenshots/cve_search_input.png',
      altText: 'ThreatPrior AI search input bar showing CVE identifier entry and Analyze trigger action',
      description:
        'The search input validates standard CVE formats (e.g. CVE-2021-44228) and dispatches concurrent requests across upstream threat intelligence feeds.',
      callouts: [
        {
          number: 1,
          label: 'CVE Format Validation',
          explanation: 'Strict alphanumeric regex parsing rejects malformed strings before triggering downstream network calls.',
        },
        {
          number: 2,
          label: 'Instant Analyze Action',
          explanation: 'Dispatches aggregated telemetry collection from NIST NVD, CISA KEV, and FIRST.org EPSS in parallel.',
        },
      ],
    },
    {
      id: 'priority-score',
      title: '2. Priority Result & CVSS Metrics',
      subtitle: 'Multi-dimensional impact assessment and weaponization status',
      imageSrc: '/screenshots/priority_cvss_score.png',
      altText: 'ThreatPrior AI vulnerability summary showing CVSS 10.0, CISA KEV Listed status, and EPSS probability metrics',
      description:
        'Tri-metric synthesis presents CVSS base severity, authoritative CISA KEV status, and FIRST EPSS exploit likelihood in a single consolidated panel.',
      callouts: [
        {
          number: 1,
          label: 'CVSS v3.1 Severity Rating',
          explanation: 'Displays official base score alongside parsed vector metrics (attack vector, attack complexity, privileges required).',
        },
        {
          number: 2,
          label: 'CISA KEV Threat Verification',
          explanation: 'Discloses active weaponization, known ransomware campaigns, and federal directive remediation deadlines.',
        },
        {
          number: 3,
          label: 'FIRST EPSS Likelihood',
          explanation: 'Empirical 30-day exploitation probability percentile calibrated from live attack sensor telemetry.',
        },
      ],
    },
    {
      id: 'ai-rationale',
      title: '3. AI Engine Status & Claude Rationale',
      subtitle: 'Two-stage decision confidence and synthesized operational guidance',
      imageSrc: '/screenshots/ai_engine_rationale.png',
      altText: 'ThreatPrior AI recommendation panel with Strands Decider 2B status and Claude Sonnet 4.6 natural language rationale',
      description:
        'Visualizes the two-stage AI output: Strands Decider 2B establishes the baseline priority rating, followed by Amazon Bedrock Claude Sonnet 4.6 synthesizing defense rationale.',
      callouts: [
        {
          number: 1,
          label: 'Dual-AI Operational Provenance',
          explanation: 'Transparent badges confirm model identifiers (strands-decider-2b, claude-sonnet-4-6) and confidence levels.',
        },
        {
          number: 2,
          label: 'Claude Reasoning Synthesis',
          explanation: 'Explains technical exploitation vectors and justifies the priority assignment based on observed evidence.',
        },
        {
          number: 3,
          label: 'Step-by-Step Remediation',
          explanation: 'Generates structured mitigation procedures including patch validation, CPE discovery, and egress detection rules.',
        },
      ],
    },
    {
      id: 'intel-sources',
      title: '4. Threat Intelligence Dossier',
      subtitle: 'Auditable evidence proof from upstream authorities',
      imageSrc: '/screenshots/threat_intelligence_sources.png',
      altText: 'Collapsible threat intelligence accordions showing NVD record telemetry, CISA KEV dates, and EPSS score details',
      description:
        'Collapsible accordions provide raw upstream proof from NIST NVD, CISA KEV, and FIRST EPSS so analysts can audit raw vulnerability metadata.',
      callouts: [
        {
          number: 1,
          label: 'NIST NVD Abstract & CPEs',
          explanation: 'Comprehensive vulnerability description, publication timestamps, and affected vendor CPE configurations.',
        },
        {
          number: 2,
          label: 'CISA KEV Directive Due Dates',
          explanation: 'Binding Operational Directive 22-01 mandates and enforcement deadlines for government and enterprise assets.',
        },
        {
          number: 3,
          label: 'EPSS Score Percentile',
          explanation: 'Empirical percentile score showing where this vulnerability ranks relative to all scored historical CVEs.',
        },
      ],
    },
    {
      id: 'risk-validation',
      title: '5. Risk Validation & Policy Safeguards',
      subtitle: 'Deterministic guardrails detecting model-evidence disagreements',
      imageSrc: '/screenshots/risk_validation_limitations.png',
      altText: 'Risk validation panel displaying policy agreement status, factual risk factors, and evidence limitations',
      description:
        'Deterministic rule validation cross-examines the AI model decision against hard security policies, surfacing disagreements and disclosing data limitations.',
      callouts: [
        {
          number: 1,
          label: 'Agreement & Disagreement Guardrail',
          explanation: 'Flags policy divergence (e.g. if an AI model classifies an actively exploited CISA KEV flaw as low priority).',
        },
        {
          number: 2,
          label: 'Evidence Limitations Disclosure',
          explanation: 'Explicitly identifies unconfirmed patch versions, synthetic command syntax, or upstream registry telemetry lag.',
        },
      ],
    },
    {
      id: 'audit-history',
      title: '6. Analysis History & Triage Queue',
      subtitle: 'Audit trail and persistent security operations records',
      imageSrc: '/screenshots/analysis_history_preview.png',
      altText: 'ThreatPrior AI Analysis History table with CVE records, priority badges, CVSS scores, and export controls',
      description:
        'Centralized audit history enables security teams to search prior analyses, filter by priority level or KEV status, and export audit trails to CSV.',
      callouts: [
        {
          number: 1,
          label: 'Comprehensive Audit Table',
          explanation: 'Tracks past assessments, analyst attribution, mitigation statuses, and one-click navigation to full analyses.',
        },
        {
          number: 2,
          label: 'Interactive Filtering & Export',
          explanation: 'Instantly filters records by severity, CISA KEV presence, or search query with one-click CSV export.',
        },
      ],
    },
  ];

  // Section E: Educational components data
  const componentExplanations: ComponentExplanation[] = [
    {
      id: 'priority',
      title: 'Priority',
      badge: 'Core Output',
      badgeColor: 'bg-primary/10 text-primary border-primary/30',
      summary: 'Actionable triage categorization (P1 Critical through P4 Low) determined by Strands Decider 2B.',
      detail:
        'Unlike static CVSS scores that measure theoretical severity, ThreatPrior AI priority reflects operational urgency. A Critical (P1) assignment signals immediate weaponization risk demanding isolation or emergency patching within 24–48 hours, while P3/P4 flaws are routed into routine maintenance cycles.',
      technicalMetric: 'Classes: Priority 1 (Immediate), Priority 2 (Expedited), Priority 3 (Standard), Priority 4 (Low/Informational).',
      icon: 'priority_high',
    },
    {
      id: 'cvss',
      title: 'CVSS Score & Vector',
      badge: 'Base Severity',
      badgeColor: 'bg-amber-400/10 text-amber-400 border-amber-400/30',
      summary: 'Standardized Common Vulnerability Scoring System (v3.1) base severity rating and attack specification.',
      detail:
        'CVSS v3.1 evaluates intrinsic vulnerability attributes without contextual threat intelligence. The vector string details attack vector (Network vs Local), attack complexity (Low vs High), privileges required, user interaction, and scope changes across Confidentiality, Integrity, and Availability.',
      technicalMetric: 'Scale: 0.0–10.0 (Low: 0.1–3.9, Medium: 4.0–6.9, High: 7.0–8.9, Critical: 9.0–10.0).',
      icon: 'speed',
    },
    {
      id: 'epss',
      title: 'FIRST EPSS Probability',
      badge: 'Predictive Threat',
      badgeColor: 'bg-secondary/10 text-secondary border-secondary/30',
      summary: 'FIRST.org empirical probability that a vulnerability will be actively exploited in the next 30 days.',
      detail:
        'The Exploit Prediction Scoring System (EPSS) applies statistical models against real-world threat telemetry to quantify exploitation likelihood. While 95% of vulnerabilities have EPSS scores below 5%, scores above 20% place a CVE in the top percentiles of threat likelihood.',
      technicalMetric: 'Range: 0.0% to 100.0% probability with corresponding historical percentile rank.',
      icon: 'trending_up',
    },
    {
      id: 'cisa-kev',
      title: 'CISA KEV Catalog',
      badge: 'Observed Threat',
      badgeColor: 'bg-error/10 text-error border-error/30',
      summary: 'Authoritative confirmation whether a vulnerability is actively exploited by threat actors in the wild.',
      detail:
        'Maintained by the US Cybersecurity & Infrastructure Security Agency, the Known Exploited Vulnerabilities (KEV) catalog tracks flaws with confirmed weaponization. Catalog inclusion triggers Binding Operational Directive (BOD) 22-01 remediation deadlines for federal systems and represents undeniable risk.',
      technicalMetric: 'Statuses: LISTED (Active in-wild exploitation / ransomware use) or NOT_LISTED (Absence does not imply safety).',
      icon: 'gavel',
    },
    {
      id: 'claude-rationale',
      title: 'Claude Rationale & Remediation',
      badge: 'Stage-2 Reasoning',
      badgeColor: 'bg-primary/10 text-primary border-primary/30',
      summary: 'Amazon Bedrock Claude Sonnet 4.6 natural language explanation and defense guidance.',
      detail:
        'When Bedrock succeeds, Claude Sonnet 4.6 synthesizes technical telemetry into human-readable executive rationale, explaining attacker vectors, enterprise exposure impact, and concrete multi-step remediation procedures tailored to the specific software stack.',
      technicalMetric: 'Powered by au.anthropic.claude-sonnet-4-6 via Amazon Bedrock serverless inference.',
      icon: 'neurology',
    },
    {
      id: 'risk-validation',
      title: 'Evidence Validation Guardrail',
      badge: 'Safety Policy',
      badgeColor: 'bg-secondary/10 text-secondary border-secondary/30',
      summary: 'Deterministic policy rule comparison that cross-examines model priority against empirical evidence.',
      detail:
        'ThreatPrior AI includes a built-in safety net: a deterministic ruleset independently evaluates NVD, KEV, and EPSS facts. If an AI model under-prioritizes an actively weaponized vulnerability, a Policy Disagreement warning is raised to alert SOC operators to review evidence.',
      technicalMetric: 'Outcomes: Agreement (Model aligned with deterministic rules) or Disagreement (Policy override suggested).',
      icon: 'policy',
    },
    {
      id: 'engine-status',
      title: 'Engine Status & Degradation',
      badge: 'Operational Transparency',
      badgeColor: 'bg-surface-container-high text-on-surface-variant border-outline-variant/40',
      summary: 'Truthful disclosure of whether dual-AI succeeded or the application operated in a degraded state.',
      detail:
        'Rather than concealing failures, ThreatPrior AI discloses pipeline state: Dual-AI (both stages succeeded), Decider-Only (Bedrock timed out or failed), Bedrock-Only (Decider failed), or Baseline Fallback (rule heuristic active). Confidence metrics are labeled as uncalibrated when applicable.',
      technicalMetric: 'Operational modes: dual-ai, decider-only, bedrock-only, baseline-heuristic.',
      icon: 'hub',
    },
    {
      id: 'evidence-limitations',
      title: 'Evidence Limitations',
      badge: 'Analytical Honesty',
      badgeColor: 'bg-amber-400/10 text-amber-400 border-amber-400/30',
      summary: 'Disclosures detailing missing upstream telemetry, unverified CLI commands, or source registry lag.',
      detail:
        'AI generation can produce plausible but unverified recommendations. ThreatPrior AI surfaces explicit warnings when patch versions cannot be validated against official CPE registries or when remediation commands represent AI synthesis requiring human review before execution.',
      technicalMetric: 'Audited caveats: Unconfirmed target patch versions, synthetic shell syntax, upstream cache staleness.',
      icon: 'warning',
    },
  ];

  // Section G: Recent Analyses from DEMO_AUDIT_HISTORY
  const recentAnalyses: AuditRecord[] = DEMO_AUDIT_HISTORY.slice(0, 3);

  const activeWalkthrough =
    screenshotItems.find((item) => item.id === activeScreenshotTab) || screenshotItems[0];

  return (
    <div className="w-full bg-background text-on-surface pb-20">
      {/* =========================================================================
          SECTION B — HERO
         ========================================================================= */}
      <section className="relative px-margin py-16 md:py-24 border-b border-surface-container-high/50 bg-radial-[at_top_center] from-surface-container-low/60 via-background to-background">
        <div className="max-w-5xl mx-auto flex flex-col items-center text-center space-y-space-lg">
          {/* Status pill */}
          <div className="inline-flex items-center gap-space-xs px-space-md py-1 rounded-full bg-surface-container-high/80 border border-primary/30 text-primary font-code-sm text-code-sm">
            <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
            <span className="uppercase tracking-wider font-semibold">Autonomous Cybersecurity Triage Platform</span>
          </div>

          {/* Headline */}
          <h1 className="font-display text-4xl sm:text-5xl md:text-6xl font-extrabold tracking-tight text-on-surface leading-tight max-w-4xl">
            Know What to Fix First.
          </h1>

          {/* Description */}
          <p className="font-body-lg text-body-lg sm:text-xl text-on-surface-variant max-w-3xl leading-relaxed">
            ThreatPrior AI combines AI-driven decision-making with real-world vulnerability intelligence to help security
            teams prioritize vulnerabilities and understand why they matter.
          </p>

          {/* Hero CTAs */}
          <div className="flex flex-col sm:flex-row items-center gap-space-md pt-space-sm">
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

          {/* Interactive Sample CVE Card */}
          <div className="pt-space-md w-full max-w-2xl">
            <div
              id="hero-sample-cve-pill"
              onClick={() => handleSampleCveClick('CVE-2021-44228')}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => e.key === 'Enter' && handleSampleCveClick('CVE-2021-44228')}
              className="group p-space-md rounded-xl bg-surface-container-low/90 hover:bg-surface-container border border-surface-container-high hover:border-primary/40 transition-all cursor-pointer flex flex-col sm:flex-row items-start sm:items-center justify-between gap-space-sm text-left shadow-sm"
              title="Click to analyze Log4Shell benchmark in Vulnerability Analysis"
            >
              <div className="flex items-center gap-space-md">
                <div className="w-10 h-10 rounded-lg bg-error/10 border border-error/30 flex items-center justify-center text-error font-code-sm font-bold">
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
                  <p className="text-on-surface-variant font-body-sm text-body-sm pt-0.5">
                    Benchmark exploit · CISA KEV Listed · Instant prefill available
                  </p>
                </div>
              </div>

              <div className="inline-flex items-center gap-1 text-primary font-code-sm text-code-sm font-medium group-hover:translate-x-0.5 transition-transform">
                <span>Analyze Sample CVE</span>
                <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION C — HOW IT WORKS
         ========================================================================= */}
      <section id="how-it-works" className="px-margin py-16 max-w-6xl mx-auto space-y-space-xl">
        <div className="text-center space-y-space-xs max-w-2xl mx-auto">
          <div className="inline-flex items-center gap-1 text-secondary font-code-sm text-code-sm uppercase tracking-wider font-semibold">
            <span className="material-symbols-outlined text-[16px]">schema</span>
            <span>Tri-Phase Workflow</span>
          </div>
          <h2 className="font-headline-lg text-headline-lg font-bold text-on-surface tracking-tight">
            How ThreatPrior AI Works
          </h2>
          <p className="font-body-md text-body-md text-on-surface-variant">
            From raw vulnerability identifier to defensible remediation in three transparent stages.
          </p>
        </div>

        {/* 3 Step responsive grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-space-lg">
          {/* Step 1 */}
          <div className="p-space-lg rounded-xl bg-surface-container-low border border-surface-container-high flex flex-col justify-between space-y-space-md group hover:border-primary/40 transition-colors">
            <div className="space-y-space-sm">
              <div className="flex items-center justify-between">
                <span className="font-code-lg text-code-lg font-bold text-primary">01</span>
                <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-high text-on-surface-variant">
                  Input Stage
                </span>
              </div>
              <h3 className="font-headline-sm text-headline-sm font-semibold text-on-surface">
                Step 1: Enter a CVE
              </h3>
              <p className="font-body-md text-body-md text-on-surface-variant leading-relaxed">
                The user enters a valid CVE identifier, such as <code className="text-primary font-code-sm">CVE-2021-44228</code>,
                on the Vulnerability Analysis page. The system aggregates real-time records from NIST NVD, CISA KEV, and FIRST EPSS.
              </p>
            </div>

            <div className="pt-space-sm border-t border-surface-container-high/60">
              <div className="flex items-center gap-space-xs text-on-surface-variant font-code-sm text-code-sm">
                <span className="material-symbols-outlined text-primary text-[18px]">verified</span>
                <span>Validates syntax &amp; aggregates telemetry</span>
              </div>
            </div>
          </div>

          {/* Step 2 */}
          <div className="p-space-lg rounded-xl bg-surface-container-low border border-surface-container-high flex flex-col justify-between space-y-space-md group hover:border-secondary/40 transition-colors">
            <div className="space-y-space-sm">
              <div className="flex items-center justify-between">
                <span className="font-code-lg text-code-lg font-bold text-secondary">02</span>
                <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-high text-on-surface-variant">
                  Decision Stage
                </span>
              </div>
              <h3 className="font-headline-sm text-headline-sm font-semibold text-on-surface">
                Step 2: Evaluate vulnerability priority
              </h3>
              <p className="font-body-md text-body-md text-on-surface-variant leading-relaxed">
                Strands Decider 2B performs the first-stage priority decision using the vulnerability evidence supplied by the
                application, classifying the flaw from Priority 1 (Immediate) through Priority 4 (Low).
              </p>
            </div>

            <div className="pt-space-sm border-t border-surface-container-high/60">
              <div className="flex items-center gap-space-xs text-on-surface-variant font-code-sm text-code-sm">
                <span className="material-symbols-outlined text-secondary text-[18px]">bolt</span>
                <span>Fast System-1 decider inference</span>
              </div>
            </div>
          </div>

          {/* Step 3 */}
          <div className="p-space-lg rounded-xl bg-surface-container-low border border-surface-container-high flex flex-col justify-between space-y-space-md group hover:border-tertiary-container/40 transition-colors">
            <div className="space-y-space-sm">
              <div className="flex items-center justify-between">
                <span className="font-code-lg text-code-lg font-bold text-tertiary-container">03</span>
                <span className="px-2 py-0.5 rounded font-code-sm text-code-sm bg-surface-container-high text-on-surface-variant">
                  Reasoning Stage
                </span>
              </div>
              <h3 className="font-headline-sm text-headline-sm font-semibold text-on-surface">
                Step 3: Understand the assessment
              </h3>
              <p className="font-body-md text-body-md text-on-surface-variant leading-relaxed">
                Amazon Bedrock Claude Sonnet 4.6 provides the second-stage rationale and recommendations when that stage
                succeeds. Users can inspect the evidence, risk validation, and any limitations affecting the assessment.
              </p>
            </div>

            <div className="pt-space-sm border-t border-surface-container-high/60">
              <div className="flex items-center gap-space-xs text-on-surface-variant font-code-sm text-code-sm">
                <span className="material-symbols-outlined text-tertiary-container text-[18px]">neurology</span>
                <span>Synthesized rationale &amp; remediation steps</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION D — ACTUAL ANNOTATED SCREENSHOTS WALKTHROUGH
         ========================================================================= */}
      <section className="px-margin py-16 bg-surface-container-lowest/70 border-y border-surface-container-high/50">
        <div className="max-w-6xl mx-auto space-y-space-xl">
          <div className="text-center space-y-space-xs max-w-3xl mx-auto">
            <div className="inline-flex items-center gap-1 text-primary font-code-sm text-code-sm uppercase tracking-wider font-semibold">
              <span className="material-symbols-outlined text-[16px]">photo_camera</span>
              <span>Genuine Platform Interface</span>
            </div>
            <h2 className="font-headline-lg text-headline-lg font-bold text-on-surface tracking-tight">
              Interactive Component Walkthrough
            </h2>
            <p className="font-body-md text-body-md text-on-surface-variant">
              Actual screenshots captured from the running ThreatPrior AI application. Select a component to inspect its
              annotations, metrics, and operational capabilities.
            </p>
          </div>

          {/* Screenshot selector tabs */}
          <div className="flex items-center justify-start sm:justify-center gap-space-xs overflow-x-auto pb-2" role="tablist">
            {screenshotItems.map((item) => (
              <button
                key={item.id}
                id={`screenshot-tab-${item.id}`}
                role="tab"
                aria-selected={activeScreenshotTab === item.id}
                type="button"
                onClick={() => setActiveScreenshotTab(item.id)}
                className={`px-space-md py-2 rounded-lg font-code-sm text-code-sm whitespace-nowrap transition-all cursor-pointer ${
                  activeScreenshotTab === item.id
                    ? 'bg-primary text-on-primary font-semibold shadow-md shadow-primary/10'
                    : 'bg-surface-container text-on-surface-variant hover:text-on-surface hover:bg-surface-container-high'
                }`}
              >
                {item.title.split('. ')[1] || item.title}
              </button>
            ))}
          </div>

          {/* Walkthrough Display Container */}
          <div className="rounded-xl bg-surface-container-low border border-surface-container-high overflow-hidden shadow-xl grid grid-cols-1 lg:grid-cols-12">
            {/* Left: Component Screenshot Preview */}
            <div className="lg:col-span-8 p-space-lg bg-surface-container-lowest flex flex-col justify-center items-center border-b lg:border-b-0 lg:border-r border-surface-container-high">
              <div className="w-full rounded-lg overflow-hidden border border-surface-container-highest/60 bg-surface-container-lowest shadow-md">
                <img
                  src={activeWalkthrough.imageSrc}
                  alt={activeWalkthrough.altText}
                  className="w-full h-auto object-cover max-h-[460px]"
                />
              </div>
              <p className="text-on-surface-variant font-code-sm text-code-sm pt-space-sm text-center">
                Captured directly from live application instance · Zero stock or synthetic graphics
              </p>
            </div>

            {/* Right: Component Annotations & Callouts */}
            <div className="lg:col-span-4 p-space-lg flex flex-col justify-between space-y-space-md">
              <div className="space-y-space-sm">
                <div>
                  <span className="font-code-sm text-code-sm uppercase tracking-wider text-secondary font-semibold">
                    {activeWalkthrough.subtitle}
                  </span>
                  <h3 className="font-headline-md text-headline-md font-bold text-on-surface pt-1">
                    {activeWalkthrough.title}
                  </h3>
                </div>

                <p className="font-body-md text-body-md text-on-surface-variant leading-relaxed">
                  {activeWalkthrough.description}
                </p>

                {/* Numbered Callouts */}
                <div className="space-y-space-sm pt-space-xs">
                  <div className="font-label-sm text-label-sm uppercase tracking-wider text-on-surface-variant font-semibold">
                    Annotated Callouts:
                  </div>
                  {activeWalkthrough.callouts.map((callout) => (
                    <div
                      key={callout.number}
                      className="p-space-sm rounded-lg bg-surface-container/70 border border-surface-container-highest/60 space-y-0.5"
                    >
                      <div className="flex items-center gap-space-xs">
                        <span className="w-5 h-5 rounded-full bg-primary/20 text-primary font-code-sm text-code-sm flex items-center justify-center font-bold">
                          {callout.number}
                        </span>
                        <span className="font-code-sm text-code-sm font-semibold text-on-surface">
                          {callout.label}
                        </span>
                      </div>
                      <p className="font-body-sm text-body-sm text-on-surface-variant pl-7">
                        {callout.explanation}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Action to try in app */}
              <button
                type="button"
                onClick={() => onNavigate('analyze')}
                className="w-full inline-flex items-center justify-center gap-space-xs px-space-md py-2.5 rounded-lg bg-surface-container-high hover:bg-surface-container-highest text-primary font-code-sm text-code-sm font-medium border border-surface-container-highest transition-colors cursor-pointer"
              >
                <span>Open in Vulnerability Analysis</span>
                <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION E — UNDERSTAND THE ANALYSIS COMPONENTS
         ========================================================================= */}
      <section id="component-glossary-section" className="px-margin py-16 max-w-6xl mx-auto space-y-space-xl">
        <div className="text-center space-y-space-xs max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-1 text-secondary font-code-sm text-code-sm uppercase tracking-wider font-semibold">
            <span className="material-symbols-outlined text-[16px]">school</span>
            <span>Technical Glossary</span>
          </div>
          <h2 className="font-headline-lg text-headline-lg font-bold text-on-surface tracking-tight">
            Understand the Analysis Components
          </h2>
          <p className="font-body-md text-body-md text-on-surface-variant">
            Key fields and signals synthesized during vulnerability triage. Expand any card to inspect technical definitions and
            analytical methodology.
          </p>
        </div>

        {/* 8 Component Cards in 2x4 responsive grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-space-md">
          {componentExplanations.map((item) => {
            const isExpanded = !!expandedComponents[item.id];
            return (
              <div
                key={item.id}
                id={`component-card-${item.id}`}
                className="p-space-md rounded-xl bg-surface-container-low border border-surface-container-high flex flex-col justify-between space-y-space-sm hover:border-primary/30 transition-colors"
              >
                <div className="space-y-space-xs">
                  <div className="flex items-center justify-between">
                    <div className="w-8 h-8 rounded-lg bg-surface-container flex items-center justify-center text-primary">
                      <span className="material-symbols-outlined text-[18px]">{item.icon}</span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[11px] font-code-sm font-semibold border ${item.badgeColor}`}>
                      {item.badge}
                    </span>
                  </div>

                  <h3 className="font-headline-sm text-headline-sm font-semibold text-on-surface pt-1">
                    {item.title}
                  </h3>

                  <p className="font-body-sm text-body-sm text-on-surface-variant leading-relaxed">
                    {item.summary}
                  </p>

                  {/* Expandable Technical Detail */}
                  {isExpanded && (
                    <div className="pt-space-xs space-y-space-xs text-code-sm text-on-surface-variant border-t border-surface-container-high/70 mt-space-xs">
                      <p className="font-body-sm text-body-sm text-on-surface leading-normal">
                        {item.detail}
                      </p>
                      <div className="p-space-xs rounded bg-surface-container text-[11px] text-secondary font-code-sm">
                        {item.technicalMetric}
                      </div>
                    </div>
                  )}
                </div>

                <button
                  id={`toggle-detail-${item.id}`}
                  type="button"
                  aria-expanded={isExpanded}
                  onClick={() => toggleComponentDetail(item.id)}
                  className="pt-space-xs flex items-center justify-between text-primary hover:text-on-surface font-code-sm text-code-sm font-medium transition-colors cursor-pointer w-full"
                >
                  <span>{isExpanded ? 'Show less' : 'Learn more'}</span>
                  <span className="material-symbols-outlined text-[16px]">
                    {isExpanded ? 'expand_less' : 'expand_more'}
                  </span>
                </button>
              </div>
            );
          })}
        </div>
      </section>

      {/* =========================================================================
          SECTION F — MEET THE INTELLIGENCE SOURCES & AI ENGINES
         ========================================================================= */}
      <section id="architecture-section" className="px-margin py-16 bg-surface-container-lowest/70 border-y border-surface-container-high/50">
        <div className="max-w-6xl mx-auto space-y-space-xl">
          <div className="text-center space-y-space-xs max-w-3xl mx-auto">
            <div className="inline-flex items-center gap-1 text-primary font-code-sm text-code-sm uppercase tracking-wider font-semibold">
              <span className="material-symbols-outlined text-[16px]">architecture</span>
              <span>Platform Architecture</span>
            </div>
            <h2 className="font-headline-lg text-headline-lg font-bold text-on-surface tracking-tight">
              Intelligence Sources &amp; AI Engines
            </h2>
            <p className="font-body-md text-body-md text-on-surface-variant">
              ThreatPrior AI separates structured evidence ingestion from multi-stage generative reasoning.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-space-lg">
            {/* Left Card: Upstream Threat Intelligence Feeds */}
            <div className="p-space-lg rounded-xl bg-surface-container-low border border-surface-container-high space-y-space-md">
              <div className="flex items-center gap-space-sm border-b border-surface-container-high pb-space-sm">
                <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/30 flex items-center justify-center text-primary">
                  <span className="material-symbols-outlined text-[22px]">database</span>
                </div>
                <div>
                  <h3 className="font-headline-sm text-headline-sm font-bold text-on-surface">
                    Upstream Intelligence Sources
                  </h3>
                  <p className="font-code-sm text-code-sm text-on-surface-variant">
                    Authoritative telemetry ingested per analysis
                  </p>
                </div>
              </div>

              <div className="space-y-space-md">
                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-headline-sm text-body-md font-semibold text-primary">NIST NVD</span>
                    <span className="text-[11px] font-code-sm px-1.5 py-0.5 rounded bg-surface-container text-on-surface-variant">
                      National Vulnerability Database
                    </span>
                  </div>
                  <p className="font-body-sm text-body-sm text-on-surface-variant">
                    Provides official vulnerability descriptions, published/modified dates, CVSS v3.1 base scoring, and affected product Common Platform Enumeration (CPE) configurations.
                  </p>
                </div>

                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-headline-sm text-body-md font-semibold text-error">CISA KEV</span>
                    <span className="text-[11px] font-code-sm px-1.5 py-0.5 rounded bg-surface-container text-on-surface-variant">
                      Known Exploited Vulnerabilities
                    </span>
                  </div>
                  <p className="font-body-sm text-body-sm text-on-surface-variant">
                    Authoritative US government registry of vulnerabilities actively exploited by threat actors and ransomware groups in the wild, establishing Binding Operational Directive due dates.
                  </p>
                </div>

                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-headline-sm text-body-md font-semibold text-secondary">FIRST EPSS</span>
                    <span className="text-[11px] font-code-sm px-1.5 py-0.5 rounded bg-surface-container text-on-surface-variant">
                      Exploit Prediction Scoring
                    </span>
                  </div>
                  <p className="font-body-sm text-body-sm text-on-surface-variant">
                    FIRST.org predictive machine-learning score estimating empirical 30-day weaponization probability, distinguishing theoretically severe flaws from actively targeted systems.
                  </p>
                </div>
              </div>
            </div>

            {/* Right Card: Two-Stage AI Decision Architecture */}
            <div className="p-space-lg rounded-xl bg-surface-container-low border border-surface-container-high space-y-space-md">
              <div className="flex items-center gap-space-sm border-b border-surface-container-high pb-space-sm">
                <div className="w-10 h-10 rounded-lg bg-secondary/10 border border-secondary/30 flex items-center justify-center text-secondary">
                  <span className="material-symbols-outlined text-[22px]">smart_toy</span>
                </div>
                <div>
                  <h3 className="font-headline-sm text-headline-sm font-bold text-on-surface">
                    Two-Stage AI Decision Architecture
                  </h3>
                  <p className="font-code-sm text-code-sm text-on-surface-variant">
                    Distinct responsibilities with graceful degradation
                  </p>
                </div>
              </div>

              <div className="space-y-space-md">
                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-headline-sm text-body-md font-semibold text-secondary">
                      Stage 1: Strands Decider 2B
                    </span>
                    <span className="text-[11px] font-code-sm px-1.5 py-0.5 rounded bg-surface-container text-secondary">
                      Fast Priority Decider
                    </span>
                  </div>
                  <p className="font-body-sm text-body-sm text-on-surface-variant">
                    A specialized, lightweight model responsible solely for rapid, deterministic classification of the priority tier (Critical, High, Medium, Low) directly from structured threat evidence.
                  </p>
                </div>

                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-headline-sm text-body-md font-semibold text-primary">
                      Stage 2: Amazon Bedrock Claude Sonnet 4.6
                    </span>
                    <span className="text-[11px] font-code-sm px-1.5 py-0.5 rounded bg-surface-container text-primary">
                      Reasoning &amp; Guidance
                    </span>
                  </div>
                  <p className="font-body-sm text-body-sm text-on-surface-variant">
                    An advanced foundation model that synthesizes human-readable operational rationale, analyzes enterprise attack surfaces, and formulates prioritized, multi-step remediation procedures.
                  </p>
                </div>

                {/* Important architectural caveat */}
                <div className="p-space-sm rounded-lg bg-surface-container/70 border border-outline-variant/30 space-y-1">
                  <div className="flex items-center gap-1.5 text-amber-400 font-code-sm text-code-sm font-semibold">
                    <span className="material-symbols-outlined text-[16px]">info</span>
                    <span>Operational Transparency Guarantee</span>
                  </div>
                  <p className="font-body-sm text-body-sm text-on-surface-variant">
                    Upstream source rate limits or model timeouts degrade gracefully to single-stage or rule-based heuristics. Automated assessments assist but never substitute for certified security engineer review.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* =========================================================================
          SECTION G — RECENT ANALYSIS PREVIEW
         ========================================================================= */}
      <section className="px-margin py-16 max-w-6xl mx-auto space-y-space-lg">
        <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-space-sm">
          <div>
            <div className="inline-flex items-center gap-1 text-secondary font-code-sm text-code-sm uppercase tracking-wider font-semibold">
              <span className="material-symbols-outlined text-[16px]">history</span>
              <span>Triage Queue Preview</span>
            </div>
            <h2 className="font-headline-lg text-headline-lg font-bold text-on-surface tracking-tight">
              Recent Vulnerability Analyses
            </h2>
            <p className="font-body-md text-body-md text-on-surface-variant">
              Recent threat assessments processed by the ThreatPrior AI telemetry pipeline.
            </p>
          </div>

          <button
            id="home-view-history-btn"
            type="button"
            onClick={() => onNavigate('history')}
            className="inline-flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-surface-container-high hover:bg-surface-container-highest text-primary font-code-sm text-code-sm font-medium border border-surface-container-highest transition-colors cursor-pointer self-start sm:self-auto"
          >
            <span>View Full Analysis History</span>
            <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
          </button>
        </div>

        {/* Recent Analysis Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-space-md">
          {recentAnalyses.map((record) => (
            <div
              key={record.id}
              onClick={() => handleSampleCveClick(record.cve)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => e.key === 'Enter' && handleSampleCveClick(record.cve)}
              className="p-space-md rounded-xl bg-surface-container-low border border-surface-container-high hover:border-primary/40 transition-all cursor-pointer flex flex-col justify-between space-y-space-md group shadow-sm"
              title={`Inspect analysis for ${record.cve}`}
            >
              <div className="space-y-space-xs">
                <div className="flex items-center justify-between">
                  <span className="font-code-md text-code-md font-bold text-primary group-hover:underline">
                    {record.cve}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded font-code-sm text-code-sm font-semibold ${
                      record.priority === 'P1'
                        ? 'bg-error/20 text-error border border-error/30'
                        : record.priority === 'P2'
                        ? 'bg-tertiary-container/20 text-tertiary-container border border-tertiary-container/30'
                        : 'bg-amber-400/20 text-amber-400 border border-amber-400/30'
                    }`}
                  >
                    Priority {record.priority}
                  </span>
                </div>

                <h3 className="font-body-md text-body-md font-semibold text-on-surface line-clamp-1">
                  {record.title}
                </h3>

                <div className="flex items-center gap-space-md pt-space-xs text-code-sm">
                  <div>
                    <span className="text-on-surface-variant text-[11px] block">CVSS:</span>
                    <span className="font-bold text-on-surface">{record.cvss}</span>
                  </div>
                  <div>
                    <span className="text-on-surface-variant text-[11px] block">EPSS:</span>
                    <span className="font-bold text-secondary">{record.epss}</span>
                  </div>
                  <div>
                    <span className="text-on-surface-variant text-[11px] block">CISA KEV:</span>
                    <span className={`font-bold ${record.cisaKev === 'YES' ? 'text-error' : 'text-on-surface-variant'}`}>
                      {record.cisaKev}
                    </span>
                  </div>
                </div>
              </div>

              <div className="pt-space-xs border-t border-surface-container-high/60 flex items-center justify-between text-code-sm text-on-surface-variant">
                <span>{record.analyzedAt}</span>
                <span className="text-primary group-hover:translate-x-0.5 transition-transform flex items-center gap-0.5">
                  <span>Inspect</span>
                  <span className="material-symbols-outlined text-[14px]">arrow_forward</span>
                </span>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};
