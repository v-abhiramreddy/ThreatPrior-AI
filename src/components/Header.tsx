import React from 'react';
import type { DataMode } from '../types';

interface HeaderProps {
  currentTab: 'home' | 'analyze' | 'history';
  onSelectTab: (tab: 'home' | 'analyze' | 'history') => void;
  dataMode?: DataMode;
}

export const Header: React.FC<HeaderProps> = ({ currentTab, onSelectTab, dataMode = 'ready' }) => {
  const getNavTabClass = (isActive: boolean) =>
    `px-space-md py-1.5 rounded-lg text-body-sm font-medium cursor-pointer border transition-all duration-200 ease-in-out ${
      isActive
        ? 'bg-secondary/15 text-primary border-secondary/25 shadow-sm shadow-secondary/10'
        : 'text-on-surface-variant hover:text-secondary hover:bg-secondary/10 border-transparent hover:border-secondary/20'
    }`;

  return (
    <header className="fixed top-0 left-0 right-0 z-50 bg-[#071926]/90 backdrop-blur-md border-b border-secondary/25 shadow-[0_1px_12px_rgba(79,219,200,0.06)] transition-colors">
      <div className="h-14 w-full px-margin flex items-center justify-between">
        {/* Left: Brand & Navigation */}
        <div className="flex items-center gap-space-lg">
          <div
            id="brand-logo-btn"
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === 'Enter' && onSelectTab('home')}
            className="flex items-center gap-space-md cursor-pointer"
            onClick={() => onSelectTab('home')}
            title="ThreatPrior AI — Home"
          >
            <div className="w-8 h-8 rounded-lg bg-primary-container/20 border border-primary/30 flex items-center justify-center text-primary">
              <span className="material-symbols-outlined text-[20px]">security</span>
            </div>
            <div className="flex items-center gap-space-xs">
              <span className="font-headline-sm text-headline-sm text-on-surface tracking-tight font-semibold">
                ThreatPrior AI
              </span>
            </div>
          </div>

          <div className="h-4 w-px bg-surface-container-highest hidden md:block" />

          {/* Navigation Links */}
          <nav className="flex items-center gap-space-xs" aria-label="Main Navigation">
            <button
              id="nav-home-btn"
              type="button"
              onClick={() => onSelectTab('home')}
              aria-current={currentTab === 'home' ? 'page' : undefined}
              className={getNavTabClass(currentTab === 'home')}
            >
              Home
            </button>
            <button
              id="nav-analyze-btn"
              type="button"
              onClick={() => onSelectTab('analyze')}
              aria-current={currentTab === 'analyze' ? 'page' : undefined}
              className={getNavTabClass(currentTab === 'analyze')}
            >
              <span className="hidden md:inline">Vulnerability </span>Analysis
            </button>
            <button
              id="nav-history-btn"
              type="button"
              onClick={() => onSelectTab('history')}
              aria-current={currentTab === 'history' ? 'page' : undefined}
              className={getNavTabClass(currentTab === 'history')}
            >
              <span className="hidden md:inline">Analysis </span>History
            </button>
          </nav>
        </div>

        {/* Right: Telemetry pill & Actions */}
        <div className="flex items-center gap-space-md">
          {/* Dynamic DATA MODE indicator pill */}
          <div
            id="demo-mode-indicator"
            data-mode={dataMode}
            className={`flex items-center gap-space-xs px-space-sm py-1 rounded-lg font-label-sm text-label-sm border transition-all ${
              dataMode === 'live'
                ? 'bg-secondary/10 border-secondary/40 text-secondary'
                : dataMode === 'demo'
                ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                : dataMode === 'analyzing'
                ? 'bg-primary/10 border-primary/40 text-primary'
                : 'bg-surface-container-low border-outline-variant/30 text-on-surface-variant'
            }`}
            title={
              dataMode === 'live'
                ? 'Live intelligence feed active from upstream NVD, CISA KEV & EPSS sources'
                : dataMode === 'demo'
                ? 'Static offline demo fixture loaded for evaluation'
                : dataMode === 'analyzing'
                ? 'Live AI triage and threat telemetry ingestion in progress'
                : 'Threat intelligence pipeline ready — select or enter a CVE to analyze'
            }
          >
            <span
              className={`inline-block w-1.5 h-1.5 rounded-full ${
                dataMode === 'live'
                  ? 'bg-secondary animate-pulse'
                  : dataMode === 'demo'
                  ? 'bg-amber-400'
                  : dataMode === 'analyzing'
                  ? 'bg-primary animate-ping'
                  : 'bg-outline'
              }`}
            />
            <span className="uppercase tracking-wider font-code-sm font-semibold">
              {dataMode === 'live'
                ? 'Live Intelligence'
                : dataMode === 'demo'
                ? 'Offline Demo'
                : dataMode === 'analyzing'
                ? 'Analyzing'
                : 'Ready to Analyze'}
            </span>
          </div>

          <div className="h-4 w-px bg-surface-container-highest hidden sm:block" />

          <div
            className="w-8 h-8 rounded-full bg-primary flex items-center justify-center text-on-primary font-bold text-xs"
            title="SOC Operator (Simulated Session)"
          >
            <span className="material-symbols-outlined text-[18px]">person</span>
          </div>
        </div>
      </div>
    </header>
  );
};
