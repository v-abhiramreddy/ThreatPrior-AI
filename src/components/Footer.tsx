import React from 'react';

export const Footer: React.FC = () => {
  return (
    <footer className="w-full bg-surface-container-lowest border-t border-surface-container-high/40">
      <div className="w-full px-margin py-space-md flex flex-col md:flex-row items-center justify-between gap-space-sm font-code-sm text-code-sm text-on-surface-variant">
        <div>
          <span>ThreatPrior AI</span> · <span className="text-secondary font-medium">DEMO DATA MODE</span> · Telemetry Engine v1.2.4 · Synthetic Fixtures
        </div>
        <div className="flex items-center gap-space-lg flex-wrap">
          <span className="text-secondary flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-secondary"></span>
            Deterministic Mock Pipeline
          </span>
          <span>Latency: 14ms (Simulated)</span>
          <span>SEC-OPS L1 CONSOLE</span>
        </div>
      </div>
    </footer>
  );
};
