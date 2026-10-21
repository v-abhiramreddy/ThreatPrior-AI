import { useState, useEffect } from 'react';
import type { DataMode } from './types';
import { Header } from './components/Header';
import { Footer } from './components/Footer';
import { Home } from './pages/Home';
import { VulnerabilityAnalysis } from './pages/VulnerabilityAnalysis';
import { AnalysisHistory } from './pages/AnalysisHistory';

export function App() {
  const [currentTab, setCurrentTab] = useState<'home' | 'analyze' | 'history'>(() => {
    if (typeof window !== 'undefined') {
      const hash = window.location.hash.toLowerCase();
      if (hash === '#history') {
        return 'history';
      }
      if (hash === '#analyze') {
        return 'analyze';
      }
      return 'home';
    }
    return 'home';
  });
  const [selectedCve, setSelectedCve] = useState<string>('CVE-2021-44228');
  const [dataMode, setDataMode] = useState<DataMode>('ready');

  // Listen to hash changes for direct URL navigation in tests, deep links, and bookmarks
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.toLowerCase();
      if (hash === '#history') {
        setCurrentTab('history');
      } else if (hash === '#analyze') {
        setCurrentTab('analyze');
      } else {
        setCurrentTab('home');
      }
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
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
