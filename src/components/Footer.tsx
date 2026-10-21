import React from 'react';

interface FooterProps {
  onNavigate?: (tab: 'home' | 'analyze' | 'history') => void;
}

export const Footer: React.FC<FooterProps> = ({ onNavigate }) => {
  return (
    <footer className="w-full bg-surface-container-lowest border-t border-surface-container-high/50 pt-8 pb-6">
      <div className="w-full px-margin max-w-6xl mx-auto space-y-6">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-space-md">
          {/* Brand & Brief Description */}
          <div className="space-y-1 max-w-xl">
            <div className="flex items-center gap-space-xs">
              <div className="w-5 h-5 rounded bg-primary/20 border border-primary/30 flex items-center justify-center text-primary text-xs font-bold">
                TP
              </div>
              <span className="font-headline-sm text-body-md font-bold text-on-surface">ThreatPrior AI</span>
              <span className="text-on-surface-variant text-code-sm font-code-sm">· National Cyber Triage Platform</span>
            </div>
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              Combines multi-source threat intelligence (NVD, CISA KEV, EPSS) with two-stage AI reasoning (Strands Decider 2B and Claude Sonnet 4.6) for transparent, evidence-based vulnerability prioritization.
            </p>
          </div>

          {/* Direct Navigation Links */}
          <div className="flex items-center gap-space-md font-code-sm text-code-sm">
            <button
              id="footer-nav-home"
              type="button"
              onClick={() => onNavigate ? onNavigate('home') : (window.location.hash = '#home')}
              className="text-on-surface-variant hover:text-primary transition-colors cursor-pointer"
            >
              Home
            </button>
            <span className="text-surface-container-highest">·</span>
            <button
              id="footer-nav-analyze"
              type="button"
              onClick={() => onNavigate ? onNavigate('analyze') : (window.location.hash = '#analyze')}
              className="text-on-surface-variant hover:text-primary transition-colors cursor-pointer"
            >
              Vulnerability Analysis
            </button>
            <span className="text-surface-container-highest">·</span>
            <button
              id="footer-nav-history"
              type="button"
              onClick={() => onNavigate ? onNavigate('history') : (window.location.hash = '#history')}
              className="text-on-surface-variant hover:text-primary transition-colors cursor-pointer"
            >
              Analysis History
            </button>
          </div>
        </div>

        {/* Evidence & Model Limitation Note */}
        <div className="pt-4 border-t border-surface-container-high/40 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-space-sm text-code-sm text-on-surface-variant font-code-sm">
          <p className="text-[12px] text-on-surface-variant/80 max-w-3xl">
            Operational Notice: Triage decisions depend on available upstream evidence and AI model inference. Automated assessments assist operational prioritization but do not replace certified security engineering reviews.
          </p>
          <div className="text-[11px] text-outline flex items-center gap-1.5 whitespace-nowrap self-end sm:self-auto">
            <span className="w-1.5 h-1.5 rounded-full bg-secondary"></span>
            <span>Strands Decider 2B · Claude Sonnet 4.6</span>
          </div>
        </div>
      </div>
    </footer>
  );
};
