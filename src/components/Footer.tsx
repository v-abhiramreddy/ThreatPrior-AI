import React, { useState, useEffect, useRef } from 'react';

interface FooterProps {
  onNavigate?: (tab: 'home' | 'analyze' | 'history') => void;
}

export const Footer: React.FC<FooterProps> = ({ onNavigate }) => {
  const [isContactOpen, setIsContactOpen] = useState(false);
  const [copyFeedback, setCopyFeedback] = useState<string | null>(null);
  const contactModalRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  const contactEmail = 'v.abhiramreddy2007@gmail.com';

  // Handle Escape key to close modal
  useEffect(() => {
    if (!isContactOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsContactOpen(false);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    // Focus close button on open
    setTimeout(() => {
      closeButtonRef.current?.focus();
    }, 50);

    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isContactOpen]);

  const handleCopyEmail = async () => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(contactEmail);
        setCopyFeedback('Email copied to clipboard!');
      } else {
        // Fallback for older environments
        const textArea = document.createElement('textarea');
        textArea.value = contactEmail;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        setCopyFeedback('Email copied to clipboard!');
      }
    } catch {
      setCopyFeedback('Failed to copy. Please copy manually.');
    }

    setTimeout(() => {
      setCopyFeedback(null);
    }, 3000);
  };

  return (
    <>
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
                Combines multi-source threat intelligence (NVD, CISA KEV, EPSS) with two-stage AI reasoning (Strands Decider 2B and Amazon Bedrock) for transparent, evidence-based vulnerability prioritization.
              </p>
            </div>

            {/* Direct Navigation Links */}
            <div className="flex flex-wrap items-center gap-space-md font-code-sm text-code-sm">
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
              <span className="text-surface-container-highest">·</span>
              <button
                id="footer-contact-us-btn"
                type="button"
                onClick={() => setIsContactOpen(true)}
                className="text-on-surface-variant hover:text-primary transition-colors cursor-pointer inline-flex items-center gap-1"
              >
                <span className="material-symbols-outlined text-[14px]">mail</span>
                <span>Contact Us</span>
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
              <span>Strands Decider 2B · Amazon Bedrock</span>
            </div>
          </div>
        </div>
      </footer>

      {/* Contact Us Accessible Modal Popup */}
      {isContactOpen && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="contact-modal-heading"
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-xs"
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setIsContactOpen(false);
            }
          }}
        >
          <div
            ref={contactModalRef}
            className="w-full max-w-md rounded-xl bg-surface-container-low border border-surface-container-high shadow-2xl p-6 space-y-5 text-on-surface"
          >
            {/* Header with Title and Close Control */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-primary/20 border border-primary/30 flex items-center justify-center text-primary">
                  <span className="material-symbols-outlined text-[18px]">mail</span>
                </div>
                <h3 id="contact-modal-heading" className="font-headline-sm text-lg font-semibold text-on-surface">
                  Get in Touch
                </h3>
              </div>
              <button
                ref={closeButtonRef}
                id="contact-modal-close-btn"
                type="button"
                onClick={() => setIsContactOpen(false)}
                aria-label="Close dialog"
                className="w-8 h-8 rounded-lg flex items-center justify-center text-on-surface-variant hover:text-on-surface hover:bg-surface-container transition-colors cursor-pointer"
              >
                <span className="material-symbols-outlined text-[20px]">close</span>
              </button>
            </div>

            {/* Message Body */}
            <p className="font-body-md text-sm text-on-surface-variant leading-relaxed">
              Have questions, feedback, or suggestions about ThreatPrior AI? Feel free to reach out by email.
            </p>

            {/* Email Address Display */}
            <div className="p-3 rounded-lg bg-surface-container border border-surface-container-high flex items-center justify-between gap-2">
              <span id="contact-modal-email" className="font-code-sm text-sm text-primary select-all break-all">
                {contactEmail}
              </span>
              <span className="text-[11px] text-on-surface-variant/70 uppercase tracking-wider shrink-0 font-code-sm">
                Direct
              </span>
            </div>

            {/* Feedback notification if email copied */}
            {copyFeedback && (
              <div
                role="status"
                className="px-3 py-1.5 rounded-md bg-secondary/10 border border-secondary/30 text-secondary text-xs flex items-center gap-1.5"
              >
                <span className="material-symbols-outlined text-[16px]">check_circle</span>
                <span>{copyFeedback}</span>
              </div>
            )}

            {/* Action Buttons */}
            <div className="grid grid-cols-2 gap-3 pt-2">
              <a
                id="contact-send-email-btn"
                href={`mailto:${contactEmail}?subject=ThreatPrior%20AI%20Inquiry`}
                className="h-10 inline-flex items-center justify-center gap-1.5 px-4 rounded-lg bg-primary text-on-primary font-body-sm text-sm font-semibold hover:bg-primary/90 transition-colors shadow-sm cursor-pointer"
              >
                <span className="material-symbols-outlined text-[18px]">send</span>
                <span>Send Email</span>
              </a>

              <button
                id="contact-copy-email-btn"
                type="button"
                onClick={handleCopyEmail}
                className="h-10 inline-flex items-center justify-center gap-1.5 px-4 rounded-lg bg-surface-container-high hover:bg-surface-container-highest border border-surface-container-highest text-on-surface font-body-sm text-sm font-medium transition-colors cursor-pointer"
              >
                <span className="material-symbols-outlined text-[18px]">content_copy</span>
                <span>Copy Email</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
