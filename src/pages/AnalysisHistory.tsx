import React, { useState, useMemo } from 'react';
import { DEMO_AUDIT_HISTORY } from '../mockData';

interface AnalysisHistoryProps {
  onSelectCve: (cve: string) => void;
}

export const AnalysisHistory: React.FC<AnalysisHistoryProps> = ({ onSelectCve }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [priorityFilter, setPriorityFilter] = useState('ALL');
  const [kevFilter, setKevFilter] = useState('ALL');
  const [copiedToken, setCopiedToken] = useState(false);
  const [noticeMessage, setNoticeMessage] = useState<string | null>(null);

  const showNotice = (msg: string) => {
    setNoticeMessage(msg);
    setTimeout(() => setNoticeMessage(null), 3500);
  };

  const filteredRows = useMemo(() => {
    const q = searchTerm.toLowerCase().trim();
    return DEMO_AUDIT_HISTORY.filter((row) => {
      const matchesSearch =
        !q ||
        row.cve.toLowerCase().includes(q) ||
        row.title.toLowerCase().includes(q) ||
        row.analyzedBy.toLowerCase().includes(q);

      const matchesPriority = priorityFilter === 'ALL' || row.priority === priorityFilter;
      const matchesKev = kevFilter === 'ALL' || row.cisaKev === kevFilter;

      return matchesSearch && matchesPriority && matchesKev;
    });
  }, [searchTerm, priorityFilter, kevFilter]);

  const handleResetFilters = () => {
    setSearchTerm('');
    setPriorityFilter('ALL');
    setKevFilter('ALL');
  };

  const handleExportCsv = () => {
    const header = 'CVE,Title,Analyzed,Priority,CVSS,EPSS,CISA_KEV,Status\n';
    const rows = filteredRows
      .map(
        (r) =>
          `"${r.cve}","${r.title}","${r.analyzedAt}","${r.priority}","${r.cvss}","${r.epss}","${r.cisaKev}","${r.mitigationStatus}"`
      )
      .join('\n');

    const blob = new Blob([header + rows], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'threatprior_audit_history.csv');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    showNotice('Exported threatprior_audit_history.csv successfully.');
  };

  const handleCopyToken = () => {
    const token = 'tp_live_99f2b8473c091932';
    navigator.clipboard?.writeText(token);
    setCopiedToken(true);
    showNotice(`Ingest API Token copied: ${token} (Demo Token · Sandbox Simulated Credential)`);
    setTimeout(() => setCopiedToken(false), 2500);
  };

  return (
    <div className="w-full min-h-screen pb-16">
      {/* Toast Notice */}
      {noticeMessage && (
        <div
          role="status"
          className="fixed bottom-6 right-6 z-50 px-space-md py-space-sm rounded-lg bg-surface-container-high border border-primary/40 text-on-surface font-code-sm text-code-sm shadow-xl flex items-center gap-space-xs"
        >
          <span className="material-symbols-outlined text-primary text-[18px]">info</span>
          <span>{noticeMessage}</span>
        </div>
      )}

      <div className="w-full px-margin py-space-xl flex flex-col gap-space-xl max-w-7xl mx-auto">
        {/* Top Action Bar & Header Context */}
        <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-space-lg">
          <div className="flex flex-col gap-space-xs">
            <div className="flex items-center gap-space-sm font-label-sm text-label-sm uppercase tracking-wider text-primary">
              <span className="inline-block w-2 h-2 rounded-full bg-primary animate-pulse"></span>
              <span>Security Audit Trail · Telemetry Sync (Demo Data)</span>
            </div>
            <h1 className="font-headline-lg text-headline-lg text-on-surface tracking-tight font-semibold">
              Analysis History &amp; Triage Queue
            </h1>
            <p className="font-body-md text-body-md text-on-surface-variant max-w-2xl">
              Past vulnerability assessments, prioritized remediation logs, and immutable audit trails across connected runtime clusters.
            </p>
          </div>

          {/* Quick Context Actions */}
          <div className="flex items-center gap-space-sm self-start lg:self-auto">
            <button
              id="exportCsvBtn"
              type="button"
              onClick={handleExportCsv}
              className="flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-surface-container-high text-on-surface hover:bg-surface-container-highest transition-colors font-body-sm text-body-sm shadow-sm active:scale-95 cursor-pointer border border-surface-container-highest"
            >
              <span className="material-symbols-outlined text-[16px] text-primary">download</span>
              <span>Export Audit CSV</span>
            </button>
            <button
              id="resyncTelemetryBtn"
              type="button"
              onClick={() => showNotice('Simulated telemetry resync completed (Demo Mode)')}
              className="flex items-center gap-space-xs px-space-md py-2 rounded-lg bg-primary text-on-primary hover:bg-secondary transition-colors font-headline-sm text-label-md shadow-sm active:scale-95 cursor-pointer"
            >
              <span className="material-symbols-outlined text-[16px]">sync</span>
              <span>Resync Telemetry</span>
            </button>
          </div>
        </div>

        {/* 3 Compact KPI Metric Tiles */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-space-md">
          {/* Tile 1 */}
          <div className="p-space-lg rounded-xl bg-surface-container-low flex flex-col justify-between gap-space-sm relative overflow-hidden group shadow-sm hover:bg-surface-container transition-colors border border-surface-container-high">
            <div className="flex items-center justify-between text-on-surface-variant font-code-sm text-code-sm uppercase tracking-wider">
              <span>Active Triage Queue</span>
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-lg bg-surface-container-high text-error font-code-sm text-code-sm font-semibold">
                <span className="w-1.5 h-1.5 rounded-full bg-error"></span>
                SLA Critical
              </span>
            </div>
            <div className="flex items-baseline gap-space-sm mt-1">
              <span className="font-display text-display text-on-surface font-semibold tracking-tight">14</span>
              <span className="font-code-sm text-code-sm text-on-surface-variant">P1 immediate targets</span>
            </div>
            <div className="flex items-center gap-space-xs text-on-surface-variant font-label-sm text-label-sm">
              <span>
                Requires response within <strong className="text-on-surface font-medium">&lt; 4h SLA</strong>
              </span>
            </div>
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-surface-container-highest group-hover:bg-error transition-all"></div>
          </div>

          {/* Tile 2 */}
          <div className="p-space-lg rounded-xl bg-surface-container-low flex flex-col justify-between gap-space-sm relative overflow-hidden group shadow-sm hover:bg-surface-container transition-colors border border-surface-container-high">
            <div className="flex items-center justify-between text-on-surface-variant font-code-sm text-code-sm uppercase tracking-wider">
              <span>Confirmed In CISA KEV</span>
              <span className="material-symbols-outlined text-[18px] text-tertiary">shield</span>
            </div>
            <div className="flex items-baseline gap-space-sm mt-1">
              <span className="font-display text-display text-on-surface font-semibold tracking-tight">19</span>
              <span className="font-code-sm text-code-sm text-on-surface-variant">Active Exploits</span>
            </div>
            <div className="flex items-center gap-space-xs text-on-surface-variant font-label-sm text-label-sm">
              <span className="text-tertiary font-code-sm font-medium">14.8%</span>
              <span>of cluster vulnerability catalog</span>
            </div>
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-surface-container-highest group-hover:bg-tertiary transition-all"></div>
          </div>

          {/* Tile 3 */}
          <div className="p-space-lg rounded-xl bg-surface-container-low flex flex-col justify-between gap-space-sm relative overflow-hidden group shadow-sm hover:bg-surface-container transition-colors border border-surface-container-high">
            <div className="flex items-center justify-between text-on-surface-variant font-code-sm text-code-sm uppercase tracking-wider">
              <span>Average EPSS Probability</span>
              <span className="material-symbols-outlined text-[18px] text-secondary">trending_up</span>
            </div>
            <div className="flex items-baseline gap-space-sm mt-1">
              <span className="font-display text-display text-secondary font-semibold tracking-tight">34.2%</span>
              <span className="font-code-sm text-code-sm text-on-surface-variant">Mean probability</span>
            </div>
            <div className="flex items-center gap-space-xs text-on-surface-variant font-label-sm text-label-sm">
              <span>Weighted across active production nodes</span>
            </div>
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-surface-container-highest group-hover:bg-secondary transition-all"></div>
          </div>
        </div>

        {/* Operational Search & Filter Controls */}
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-space-md p-space-md rounded-xl bg-surface-container-low border border-surface-container-high">
          <div className="flex flex-1 flex-col sm:flex-row items-stretch sm:items-center gap-space-sm">
            {/* Search history input */}
            <div className="relative flex-1 min-w-[260px]">
              <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-[18px]">
                search
              </span>
              <input
                id="searchInput"
                type="text"
                aria-label="Search analysis history"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search CVE ID, service, actor, or analyst..."
                className="w-full pl-9 pr-space-md py-1.5 rounded-lg bg-surface-container-lowest text-on-surface placeholder:text-on-surface-variant/60 font-code-sm text-code-sm focus:outline-none focus:bg-surface-container-high transition-colors border border-surface-container-highest/60"
              />
            </div>

            {/* Priority Filter */}
            <div className="flex items-center gap-space-xs">
              <label htmlFor="priorityFilter" className="font-label-sm text-label-sm text-on-surface-variant uppercase pl-1">
                Priority:
              </label>
              <select
                id="priorityFilter"
                value={priorityFilter}
                onChange={(e) => setPriorityFilter(e.target.value)}
                className="px-space-md py-1.5 rounded-lg bg-surface-container-lowest text-on-surface font-code-sm text-code-sm focus:outline-none focus:bg-surface-container-high transition-colors cursor-pointer border border-surface-container-highest/60"
              >
                <option value="ALL">All Levels</option>
                <option value="P1">P1 Immediate</option>
                <option value="P2">P2 Elevated</option>
                <option value="P3">P3 Moderate</option>
                <option value="P4">P4 Informational</option>
              </select>
            </div>

            {/* CISA KEV Filter */}
            <div className="flex items-center gap-space-xs">
              <label htmlFor="kevFilter" className="font-label-sm text-label-sm text-on-surface-variant uppercase pl-1">
                KEV Status:
              </label>
              <select
                id="kevFilter"
                value={kevFilter}
                onChange={(e) => setKevFilter(e.target.value)}
                className="px-space-md py-1.5 rounded-lg bg-surface-container-lowest text-on-surface font-code-sm text-code-sm focus:outline-none focus:bg-surface-container-high transition-colors cursor-pointer border border-surface-container-highest/60"
              >
                <option value="ALL">All Entries</option>
                <option value="YES">In CISA KEV</option>
                <option value="NO">Not in KEV</option>
              </select>
            </div>
          </div>

          {/* Quick Reset & Count */}
          <div className="flex items-center justify-between sm:justify-end gap-space-md">
            <span id="filteredCount" className="font-code-sm text-code-sm text-on-surface-variant">
              Showing {filteredRows.length} of {DEMO_AUDIT_HISTORY.length} displayed
            </span>
            <button
              id="resetFiltersBtn"
              type="button"
              onClick={handleResetFilters}
              className="text-primary hover:text-on-surface font-code-sm text-code-sm flex items-center gap-1 transition-colors cursor-pointer"
            >
              <span className="material-symbols-outlined text-[14px]">filter_alt_off</span>
              <span>Clear Filters</span>
            </button>
          </div>
        </div>

        {/* Table Container / High Density Evidence View */}
        <div id="history-table-card" className="w-full rounded-xl bg-surface-container-low overflow-hidden shadow-sm border border-surface-container-high">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-surface-container-high text-on-surface-variant font-code-sm text-code-sm uppercase tracking-wider border-b border-surface-container-highest">
                  <th className="py-space-md px-space-lg font-medium">CVE Identifier &amp; Target</th>
                  <th className="py-space-md px-space-md font-medium">Analyzed</th>
                  <th className="py-space-md px-space-md font-medium">Priority Rank</th>
                  <th className="py-space-md px-space-md font-medium">CVSS &amp; EPSS</th>
                  <th className="py-space-md px-space-md font-medium">CISA KEV</th>
                  <th className="py-space-md px-space-md font-medium">Mitigation Status</th>
                  <th className="py-space-md px-space-lg text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody id="auditTableBody" className="font-body-md text-body-md divide-y divide-surface-container-highest/40">
                {filteredRows.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-space-xl text-center text-on-surface-variant font-code-sm">
                      No matching CVE records found in demo history. Try adjusting filters or search terms.
                    </td>
                  </tr>
                ) : (
                  filteredRows.map((row) => (
                    <tr
                      key={row.id}
                      data-priority={row.priority}
                      data-kev={row.cisaKev}
                      className="hover:bg-surface-container/60 transition-colors group"
                    >
                      <td className="py-space-md px-space-lg">
                        <div className="flex items-center gap-space-md">
                          <div
                            className={`w-1.5 h-8 rounded-full ${
                              row.priority === 'P1'
                                ? 'bg-error'
                                : row.priority === 'P2'
                                ? 'bg-tertiary-container'
                                : 'bg-primary'
                            }`}
                          />
                          <div className="flex flex-col">
                            <span
                              className="font-code-lg text-code-lg text-on-surface font-semibold group-hover:text-primary transition-colors cursor-pointer"
                              onClick={() => onSelectCve(row.cve)}
                            >
                              {row.cve}
                            </span>
                            <span className="font-body-sm text-body-sm text-on-surface-variant">{row.title}</span>
                          </div>
                        </div>
                      </td>

                      <td className="py-space-md px-space-md">
                        <div className="flex flex-col">
                          <span className="font-code-sm text-code-sm text-on-surface">{row.analyzedAt}</span>
                          <span className="font-label-sm text-label-sm text-on-surface-variant">{row.analyzedBy}</span>
                        </div>
                      </td>

                      <td className="py-space-md px-space-md">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-lg bg-surface-container-high font-code-sm text-code-sm font-medium ${
                            row.priority === 'P1'
                              ? 'text-error'
                              : row.priority === 'P2'
                              ? 'text-tertiary-container'
                              : 'text-primary'
                          }`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              row.priority === 'P1'
                                ? 'bg-error animate-pulse'
                                : row.priority === 'P2'
                                ? 'bg-tertiary-container'
                                : 'bg-primary'
                            }`}
                          />
                          {row.priority} - {row.priority === 'P1' ? 'Immediate' : row.priority === 'P2' ? 'Elevated' : 'Moderate'}
                        </span>
                      </td>

                      <td className="py-space-md px-space-md">
                        <div className="flex items-center gap-space-md">
                          <div className="flex flex-col">
                            <span
                              className={`font-code-md text-code-md font-semibold ${
                                parseFloat(row.cvss) >= 9.0 ? 'text-error' : 'text-tertiary-container'
                              }`}
                            >
                              {row.cvss}
                            </span>
                            <span className="font-label-sm text-label-sm text-on-surface-variant">CVSS v3</span>
                          </div>
                          <div className="flex flex-col">
                            <span className="font-code-md text-code-md text-on-surface font-medium">{row.epss}</span>
                            <span className="font-label-sm text-label-sm text-secondary">EPSS</span>
                          </div>
                        </div>
                      </td>

                      <td className="py-space-md px-space-md">
                        {row.cisaKev === 'YES' ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg bg-surface-container-high text-tertiary font-code-sm text-code-sm font-medium">
                            <span className="material-symbols-outlined text-[13px]">bolt</span>
                            Active In Wild
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-lg bg-surface-container-high text-on-surface-variant font-code-sm text-code-sm">
                            Not Listed
                          </span>
                        )}
                      </td>

                      <td className="py-space-md px-space-md">
                        <span className="inline-flex items-center gap-1.5 px-space-sm py-1 rounded-lg bg-surface-container-high text-on-surface font-code-sm text-code-sm">
                          <span className={`w-1.5 h-1.5 rounded-full ${row.mitigationColor} animate-pulse`} />
                          {row.mitigationStatus}
                        </span>
                      </td>

                      <td className="py-space-md px-space-lg text-right">
                        <div className="flex items-center justify-end gap-space-xs">
                          <button
                            type="button"
                            onClick={() => onSelectCve(row.cve)}
                            className="px-space-sm py-1 rounded-lg bg-surface-container-high text-on-surface hover:bg-surface-container-highest transition-colors font-code-sm text-code-sm cursor-pointer border border-surface-container-highest"
                          >
                            View Analysis
                          </button>
                          <button
                            type="button"
                            onClick={() => showNotice(`Re-evaluating ${row.cve} in simulation...`)}
                            title="Re-evaluate"
                            className="p-1 rounded-lg text-on-surface-variant hover:text-primary hover:bg-surface-container-high transition-colors cursor-pointer"
                          >
                            <span className="material-symbols-outlined text-[18px]">replay</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Telemetry Inspector Tray */}
        <div className="p-space-lg rounded-xl bg-surface-container-low flex flex-col md:flex-row items-center justify-between gap-space-lg border border-surface-container-high">
          <div className="flex items-center gap-space-md">
            <div className="w-10 h-10 rounded-lg bg-surface-container-high flex items-center justify-center text-primary border border-primary/20">
              <span className="material-symbols-outlined text-[20px]">terminal</span>
            </div>
            <div className="flex flex-col">
              <span className="font-headline-sm text-headline-sm text-on-surface font-medium">
                Need Raw Audit Log Ingestion?
              </span>
              <span className="font-body-sm text-body-sm text-on-surface-variant">
                ThreatPrior supports direct streaming ingestion via Splunk, Elastic, and AWS Security Lake.
              </span>
            </div>
          </div>

          <div className="flex items-center gap-space-sm w-full md:w-auto">
            <button
              id="copyTokenBtn"
              type="button"
              onClick={handleCopyToken}
              className="w-full md:w-auto px-space-md py-2 rounded-lg bg-surface-container-high text-on-surface hover:bg-surface-container-highest transition-colors font-code-sm text-code-sm flex items-center justify-center gap-space-xs cursor-pointer border border-surface-container-highest active:scale-95"
            >
              <span className="material-symbols-outlined text-[16px] text-primary">key</span>
              <span>{copiedToken ? 'Token Copied!' : 'Copy Ingest API Token'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
