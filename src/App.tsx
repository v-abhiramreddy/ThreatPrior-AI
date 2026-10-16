import { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Footer } from './components/Footer';
import { VulnerabilityAnalysis } from './pages/VulnerabilityAnalysis';
import { AnalysisHistory } from './pages/AnalysisHistory';

export function App() {
  const [currentTab, setCurrentTab] = useState<'analyze' | 'history'>(() => {
    if (typeof window !== 'undefined' && window.location.hash === '#history') {
      return 'history';
    }
    return 'analyze';
  });
  const [selectedCve, setSelectedCve] = useState<string>('CVE-2021-44228');

  // Listen to hash changes for direct URL navigation in tests and bookmarks
  useEffect(() => {
    const handleHashChange = () => {
      if (window.location.hash === '#history') {
        setCurrentTab('history');
      } else {
        setCurrentTab('analyze');
      }
    };

    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  const handleSelectTab = (tab: 'analyze' | 'history') => {
    setCurrentTab(tab);
    window.location.hash = tab === 'history' ? '#history' : '#analyze';
  };

  const handleSelectCveFromHistory = (cve: string) => {
    setSelectedCve(cve);
    handleSelectTab('analyze');
  };

  return (
    <div className="bg-background text-on-surface min-h-screen flex flex-col font-body-md antialiased selection:bg-primary/20 selection:text-primary">
      <Header currentTab={currentTab} onSelectTab={handleSelectTab} />

      <main className="flex-1 w-full pt-14 flex flex-col">
        {currentTab === 'analyze' ? (
          <VulnerabilityAnalysis initialCve={selectedCve} />
        ) : (
          <AnalysisHistory onSelectCve={handleSelectCveFromHistory} />
        )}
      </main>


      <Footer />
    </div>
  );
}

export default App;
