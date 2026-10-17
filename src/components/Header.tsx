import React from 'react';
import type { DataMode } from '../types';

interface HeaderProps {
  currentTab: 'analyze' | 'history';
  onSelectTab: (tab: 'analyze' | 'history') => void;
  dataMode?: DataMode;
}

export const Header: React.FC<HeaderProps> = ({ currentTab, onSelectTab, dataMode = 'ready' }) => {
  return (
    <header className="fixed top-0 left-0 right-0 z-50 bg-surface-container-lowest/90 backdrop-blur-md border-b border-surface-container-high/50">
      <div className="h-14 w-full px-margin flex items-center justify-between">
        {/* Left: Brand & Navigation */}
        <div className="flex items-center gap-space-lg">
          <div className="flex items-center gap-space-md cursor-pointer" onClick={() => onSelectTab('analyze')}>
            <div className="w-8 h-8 rounded-lg bg-primary-container/20 border border-primary/30 flex items-center justify-center text-primary">
              <span className="material-symbols-outlined text-[20px]">security</span>
            </div>
            <div className="flex items-center gap-space-xs">
              <span className="font-headline-sm text-headline-sm text-on-surface tracking-tight font-semibold">
                ThreatPrior AI
              </span>
              <span className="font-label-sm text-label-sm px-space-xs py-0.5 rounded-lg bg-surface-container-high text-on-surface-variant font-code-sm uppercase">
                v1.2 PROTOTYPE
              </span>
            </div>
          </div>

          <div className="h-4 w-px bg-surface-container-highest hidden sm:block" />

          {/* Navigation Links */}
          <nav className="flex items-center gap-space-xs" aria-label="Main Navigation">
            <button
              id="nav-analyze-btn"
              type="button"
              onClick={() => onSelectTab('analyze')}
              aria-current={currentTab === 'analyze' ? 'page' : undefined}
              className={`px-space-md py-1.5 transition-colors font-medium rounded-lg text-body-sm ${
                currentTab === 'analyze'
                  ? 'bg-surface-container text-primary font-medium shadow-sm'
                  : 'text-on-surface-variant hover:bg-surface-container hover:text-on-surface'
              }`}
            >
              Analyze
            </button>
            <button
              id="nav-history-btn"
              type="button"
              onClick={() => onSelectTab('history')}
              aria-current={currentTab === 'history' ? 'page' : undefined}
              className={`px-space-md py-1.5 transition-colors font-medium rounded-lg text-body-sm ${
                currentTab === 'history'
                  ? 'bg-surface-container text-primary font-medium shadow-sm'
                  : 'text-on-surface-variant hover:bg-surface-container hover:text-on-surface'
              }`}
            >
              History
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

          <div className="hidden md:flex items-center gap-space-xs px-space-sm py-1 rounded-lg bg-surface-container-low text-on-surface-variant font-code-sm text-code-sm">
            <span className="material-symbols-outlined text-[14px]">keyboard_command_key</span>
            <span>K</span>
          </div>

          <div className="h-4 w-px bg-surface-container-highest hidden sm:block" />

          <button
            id="btn-settings"
            type="button"
            className="p-1.5 rounded-lg text-on-surface-variant hover:bg-surface-container hover:text-on-surface transition-colors"
            title="Settings (Demo)"
            aria-label="Settings"
          >
            <span className="material-symbols-outlined text-[18px]">tune</span>
          </button>

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
