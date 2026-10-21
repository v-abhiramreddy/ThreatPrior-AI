import { useState, useEffect } from 'react';
import type { DataMode } from './types';
import { Header } from './components/Header';
import { Footer } from './components/Footer';
import { Home } from './pages/Home';
import { VulnerabilityAnalysis } from './pages/VulnerabilityAnalysis';
import { AnalysisHistory } from './pages/AnalysisHistory';

interface RouteState {
  tab: 'home' | 'analyze' | 'history';
  cve?: string;
}

/**
 * Robust route parser supporting:
 * - Root URL / landing page defaulting to Home
 * - Hash routes: #home, #analyze, #history
 * - Pathname routes: /analyze, /history, /vulnerabilities/:cve
 * - Query parameters: ?cve=CVE-YYYY-NNNN or #analyze?cve=CVE-YYYY-NNNN
 */
function parseRouteFromLocation(): RouteState {
  if (typeof window === 'undefined') {
    return { tab: 'home' };
  }

  const pathname = window.location.pathname.toLowerCase();
  const hash = window.location.hash.toLowerCase();
  const search = window.location.search;

  // 1. Check for CVE query param in search or hash (e.g. ?cve=CVE-2023-38606 or #analyze?cve=CVE-2023-38606)
  let cveParam: string | null = null;
  const searchParams = new URLSearchParams(search);
  if (searchParams.has('cve')) {
    cveParam = searchParams.get('cve');
  } else if (hash.includes('?')) {
    const hashQuery = hash.split('?')[1];
    const hashParams = new URLSearchParams(hashQuery);
    if (hashParams.has('cve')) {
      cveParam = hashParams.get('cve');
    }
  }

  // 2. Check for CVE in path (e.g. /vulnerabilities/CVE-2021-44228 or /analyze/CVE-2021-44228)
  const cveMatch = window.location.pathname.match(/\/(?:vulnerabilities|analyze)\/(CVE-\d{4}-\d{4,})/i);
  if (cveMatch) {
    cveParam = cveMatch[1].toUpperCase();
  }

  // If a specific CVE is requested directly, route to analyze with that CVE
  if (cveParam) {
    return { tab: 'analyze', cve: cveParam.toUpperCase() };
  }

  // 3. Check hash routes (preserves existing #analyze, #history, #home patterns)
  const cleanHash = hash.split('?')[0];
  if (cleanHash === '#history' || cleanHash.startsWith('#history/')) {
    return { tab: 'history' };
  }
  if (cleanHash === '#analyze' || cleanHash.startsWith('#analyze/')) {
    return { tab: 'analyze' };
  }
  if (cleanHash === '#home') {
    return { tab: 'home' };
  }

  // 4. Check pathname routes (e.g. direct visits to /analyze or /history on production SPA)
  if (pathname === '/history' || pathname.startsWith('/history/')) {
    return { tab: 'history' };
  }
  if (pathname === '/analyze' || pathname.startsWith('/analyze/') || pathname.startsWith('/vulnerabilities')) {
    return { tab: 'analyze' };
  }

  // 5. Default is ALWAYS home for root '/' or any unrecognized path
  return { tab: 'home' };
}

export function App() {
  const initialRoute = parseRouteFromLocation();
  const [currentTab, setCurrentTab] = useState<'home' | 'analyze' | 'history'>(initialRoute.tab);
  const [selectedCve, setSelectedCve] = useState<string>(initialRoute.cve || 'CVE-2021-44228');
  const [dataMode, setDataMode] = useState<DataMode>('ready');

  // Synchronize route state with browser URL (hash changes, back/forward popstate)
  useEffect(() => {
    const handleRouteSync = () => {
      const route = parseRouteFromLocation();
      setCurrentTab(route.tab);
      if (route.cve) {
        setSelectedCve(route.cve);
      }
    };

    window.addEventListener('hashchange', handleRouteSync);
    window.addEventListener('popstate', handleRouteSync);
    return () => {
      window.removeEventListener('hashchange', handleRouteSync);
      window.removeEventListener('popstate', handleRouteSync);
    };
  }, []);

  const handleSelectTab = (tab: 'home' | 'analyze' | 'history') => {
    setCurrentTab(tab);
    if (tab === 'history') {
      window.location.hash = '#history';
    } else if (tab === 'analyze') {
      window.location.hash = '#analyze';
    } else {
      window.location.hash = '#home';
    }
  };

  const handleSelectCve = (cve: string) => {
    setSelectedCve(cve);
    handleSelectTab('analyze');
  };

  return (
    <div className="bg-background text-on-surface min-h-screen flex flex-col font-body-md antialiased selection:bg-primary/20 selection:text-primary">
      <Header currentTab={currentTab} onSelectTab={handleSelectTab} dataMode={dataMode} />

      <main className="flex-1 w-full pt-14 flex flex-col">
        {currentTab === 'home' ? (
          <Home onNavigate={handleSelectTab} onSelectCve={handleSelectCve} />
        ) : currentTab === 'analyze' ? (
          <VulnerabilityAnalysis
            initialCve={selectedCve}
            dataMode={dataMode}
            onDataModeChange={setDataMode}
          />
        ) : (
          <AnalysisHistory onSelectCve={handleSelectCve} />
        )}
      </main>

      <Footer onNavigate={handleSelectTab} />
    </div>
  );
}

export default App;
