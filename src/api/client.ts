import type {
  VulnerabilityApiResponse,
  TriageApiResponse,
  CveData,
  RemediationStep,
  SeverityLevel,
  HistoryListResponse,
  HistoryDetailResponse,
  TelemetryResyncResponse,
} from '../types';

export class ApiError extends Error {
  status?: number;
  isOffline?: boolean;
  isAborted?: boolean;
  errors?: string[];

  constructor(
    message: string,
    options?: { status?: number; isOffline?: boolean; isAborted?: boolean; errors?: string[] }
  ) {
    super(message);
    this.name = 'ApiError';
    this.status = options?.status;
    this.isOffline = options?.isOffline;
    this.isAborted = options?.isAborted;
    this.errors = options?.errors;
  }
}

/**
 * Base URL for backend API requests.
 * Defaults to empty string (relative paths such as '/api/...') for single-service deployments
 * and local development via Vite proxy.
 * Can be overridden via VITE_API_BASE_URL when frontend and backend are hosted on different origins.
 */
export const API_BASE_URL: string = (
  typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE_URL
    ? String(import.meta.env.VITE_API_BASE_URL).trim()
    : ''
).replace(/\/+$/, '');

/**
 * Helper to construct an API endpoint URL.
 * Prefixes API_BASE_URL if set, or returns relative path.
 */
export function getApiUrl(path: string): string {
  const cleanPath = path.startsWith('/') ? path : `/${path}`;
  return API_BASE_URL ? `${API_BASE_URL}${cleanPath}` : cleanPath;
}

/**
 * Fetch aggregated vulnerability intelligence from the backend API.
 */
export async function fetchVulnerability(
  cveId: string,
  options?: { signal?: AbortSignal }
): Promise<VulnerabilityApiResponse> {
  const normalizedId = cveId.trim().toUpperCase();

  try {
    const response = await fetch(getApiUrl(`/api/vulnerabilities/${encodeURIComponent(normalizedId)}`), {
      signal: options?.signal,
      headers: {
        Accept: 'application/json',
      },
    });

    if (response.status === 400) {
      const data = await response.json().catch(() => ({}));
      throw new ApiError(data.detail || `Invalid CVE identifier format: '${cveId}'`, { status: 400 });
    }

    if (response.status === 404) {
      const data = await response.json().catch(() => ({}));
      throw new ApiError(data.detail || `Vulnerability ${cveId} not found in any upstream intelligence source.`, {
        status: 404,
        errors: data.errors,
      });
    }

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new ApiError(data.detail || `Backend returned error HTTP ${response.status}`, {
        status: response.status,
      });
    }

    const json = (await response.json()) as VulnerabilityApiResponse;
    return json;
  } catch (err) {
    if (err instanceof ApiError) {
      throw err;
    }
    if (err instanceof Error && (err.name === 'AbortError' || options?.signal?.aborted)) {
      throw new ApiError('Request was aborted.', { isAborted: true });
    }
    // Network errors (e.g. backend server not running / connection refused)
    throw new ApiError('Backend service is offline or unreachable.', { isOffline: true });
  }
}

/**
 * Fetch AI triage decision along with aggregated threat intelligence from the backend API.
 */
export async function fetchTriageDecision(
  cveId: string,
  options?: { signal?: AbortSignal }
): Promise<TriageApiResponse> {
  const normalizedId = cveId.trim().toUpperCase();

  try {
    const response = await fetch(getApiUrl(`/api/vulnerabilities/${encodeURIComponent(normalizedId)}/triage`), {
      signal: options?.signal,
      headers: {
        Accept: 'application/json',
      },
    });

    if (response.ok) {
      const json = (await response.json()) as TriageApiResponse;
      return json;
    }

    if (response.status === 400) {
      const data = await response.json().catch(() => ({}));
      throw new ApiError(data.detail || `Invalid CVE identifier format: '${cveId}'`, { status: 400 });
    }

    if (response.status === 404) {
      const data = await response.json().catch(() => ({}));
      if (data.status === 'not_found' || data.cve_id || data.detail) {
        throw new ApiError(data.detail || `Vulnerability ${cveId} not found in NVD, CISA KEV, or EPSS.`, {
          status: 404,
          errors: data.errors,
        });
      }
    }

    if (response.status === 429) {
      const data = await response.json().catch(() => ({}));
      throw new ApiError(data.detail || 'Rate limit exceeded: maximum triage requests per minute reached.', {
        status: 429,
        errors: data.errors,
      });
    }

    if (response.status === 502) {
      const data = await response.json().catch(() => null);
      if (data && (data.detail || data.cve_id || data.status)) {
        throw new ApiError(
          data.detail || `Insufficient vulnerability evidence to triage ${cveId}: Upstream intelligence sources unavailable.`,
          {
            status: 502,
            errors: data.errors,
          }
        );
      }
      // Reverse proxy / Vite proxy returned 502 because backend service is offline
      throw new ApiError('Backend service is offline or unreachable.', { isOffline: true, status: 502 });
    }

    if (response.status === 503) {
      const data = await response.json().catch(() => ({}));
      throw new ApiError(data.detail || 'AI Decision Engine is temporarily unavailable.', {
        status: 503,
        errors: data.errors,
      });
    }

    const data = await response.json().catch(() => ({}));
    throw new ApiError(data.detail || `Backend returned error HTTP ${response.status}`, {
      status: response.status,
      errors: data.errors,
    });
  } catch (err: unknown) {
    if (err instanceof ApiError) {
      throw err;
    }
    if (err instanceof Error && (err.name === 'AbortError' || options?.signal?.aborted)) {
      throw new ApiError('Request was aborted.', { isAborted: true });
    }
    throw new ApiError('Backend service is offline or unreachable.', { isOffline: true });
  }
}

/**
 * Generates a genuinely plain-English operational summary (1–2 sentences)
 * from authoritative vulnerability data.
 * Explains what the vulnerability allows an attacker or application to do and its relevant practical risk.
 * Preserves the complete original description for the Technical Description section.
 * If a reliable plain-English summary cannot be generated, returns a clearly labelled fallback.
 */
export function generateOperationalSummary(
  sourceDescription?: string | null,
  title?: string | null,
  _cveId?: string | null,
  cpeConfigurations?: string[]
): string {
  const fallbackText =
    'Operational Summary Fallback: Standardized plain-English overview unavailable from source telemetry. Refer to authoritative Technical Description below.';

  if (!sourceDescription || !sourceDescription.trim()) {
    return fallbackText;
  }

  const desc = sourceDescription.trim();
  const lower = desc.toLowerCase();

  // Reject placeholders or empty candidate records
  if (['rejected reason', 'do not use this candidate', 'reserved by', '** reject **'].some((p) => lower.includes(p))) {
    return fallbackText;
  }

  // Extract affected versions if available from CPE configurations or description
  const affectedVersions: string[] = [];
  if (cpeConfigurations) {
    for (const cpe of cpeConfigurations) {
      const parts = cpe.split(':');
      if (parts.length >= 6) {
        const v = parts[5];
        if (v && v !== '*' && v !== '-' && !affectedVersions.includes(v)) {
          affectedVersions.push(v);
        }
      }
    }
  }
  if (affectedVersions.length === 0) {
    const matches = lower.match(/\b(?:version|releases?)\s+(\d+\.\d+(?:\.\d+)?)\b/g);
    if (matches) {
      for (const m of matches) {
        const vMatch = m.match(/(\d+\.\d+(?:\.\d+)?)/);
        if (vMatch && !affectedVersions.includes(vMatch[1])) {
          affectedVersions.push(vMatch[1]);
        }
      }
    }
  }

  let cleanTitle = '';
  if (title && !title.toUpperCase().startsWith('CVE-')) {
    cleanTitle = title.replace(/^(?:Vulnerability\s+)?(?:CVE-\d{4}-\d+\s*[-:]?\s*)?/i, '').replace(/\s*\(CVE-\d{4}-\d+\)$/i, '').trim();
  }

  // 1. Supply-chain backdoor handling (prioritized to preserve supply-chain context)
  const isSupplyChain = ['malicious code', 'backdoor', 'upstream tarball', 'prebuilt object', 'supply chain', 'compromised release'].some((w) => lower.includes(w));

  if (isSupplyChain) {
    const actor = 'A supply-chain adversary or unauthorized attacker';
    const targetProd = cleanTitle ? ` of ${cleanTitle}` : '';
    let impact: string;
    if (affectedVersions.length > 0) {
      const verStr = affectedVersions.slice(0, 3).join(' and ');
      impact = `exploit unauthorized malicious code introduced into upstream releases (${verStr})${targetProd}`;
    } else {
      impact = `exploit unauthorized malicious code embedded into upstream software components${targetProd}`;
    }
    const risk = 'unauthorized function interception, remote authentication bypass, and arbitrary code execution with elevated system privileges';
    return `${actor} can ${impact}. On systems where compromised components were used, this introduces practical risk of ${risk}.`;
  }

  // 2. Determine attacker position / access vector for other vulnerability types
  let actor = 'An attacker';
  if (['remote', 'network', 'unauthenticated', 'remotely'].some((w) => lower.includes(w))) {
    actor = 'An unauthenticated remote attacker';
  } else if (['local', 'locally', 'local user', 'local application'].some((w) => lower.includes(w))) {
    actor = 'A local application or user';
  } else if (['adjacent', 'physical'].some((w) => lower.includes(w))) {
    actor = 'An attacker with adjacent network access';
  }

  // 3. Extract grounded vulnerability mechanism and practical risk
  let impactAction: string | null = null;
  let risk: string | null = null;

  if (/\b(?:remote code execution|execute arbitrary code|arbitrary code execution|rce|code execution)\b/.test(lower)) {
    impactAction = 'exploit arbitrary code execution vulnerabilities';
    risk = 'complete host takeover, internal network traversal, and unauthorized service manipulation';
  } else if (['privilege escalation', 'elevation of privilege', 'gain privileges', 'modify sensitive kernel'].some((w) => lower.includes(w))) {
    impactAction = 'bypass operating system protections to elevate privileges';
    risk = 'unauthorized administrative control and disabling of core security mechanisms';
  } else if (['memory corruption', 'buffer overflow', 'heap-based buffer', 'out-of-bounds', 'use-after-free'].some((w) => lower.includes(w))) {
    impactAction = 'corrupt memory boundaries to alter application execution';
    risk = 'unexpected process crashes or unauthorized code execution within system processes';
  } else if (['sql injection', 'command injection', 'injection vulnerability'].some((w) => lower.includes(w))) {
    impactAction = 'inject malicious commands into application processing routines';
    risk = 'unauthorized database exfiltration and arbitrary command execution';
  } else if (['credential', 'ntlm', 'information disclosure', 'sensitive information', 'information leak'].some((w) => lower.includes(w))) {
    impactAction = 'intercept or exfiltrate sensitive data and authentication credentials';
    risk = 'credential harvesting, lateral movement, and confidential record exposure';
  } else if (['bypass', 'protected view', 'sandbox', 'access control'].some((w) => lower.includes(w))) {
    impactAction = 'bypass security boundaries and isolation controls';
    risk = 'defense-in-depth compromise and unauthorized access to restricted assets';
  } else if (['denial of service', 'crash', 'resource exhaustion'].some((w) => lower.includes(w))) {
    impactAction = 'trigger unexpected service termination or resource starvation';
    risk = 'severe application outages and prolonged operational downtime';
  }

  if (!impactAction) {
    return fallbackText;
  }

  const targetClause = cleanTitle ? ` in ${cleanTitle}` : '';
  return `${actor} can ${impactAction}${targetClause}. In an enterprise environment, this introduces practical risk of ${risk}.`;
}

/**
 * Helper to map backend normalized response into frontend CveData model.
 */
export function mapBackendToCveData(res: VulnerabilityApiResponse): CveData {
  const norm = res.normalized;
  const nvd = res.provenance.nvd;
  const cisa = res.provenance.cisa_kev;
  const epss = res.provenance.epss;

  const severity = (norm?.primary_severity || 'UNKNOWN') as SeverityLevel;
  const severityColors: Record<SeverityLevel, string> = {
    CRITICAL: 'text-error',
    HIGH: 'text-tertiary-container',
    MEDIUM: 'text-amber-400',
    LOW: 'text-secondary',
    UNKNOWN: 'text-outline',
  };

  const cvssScore = norm?.cvss_score !== null && norm?.cvss_score !== undefined ? norm.cvss_score.toFixed(1) : 'N/A';
  const cvssVector = norm?.cvss_vector || 'CVSS vector specification unavailable in upstream record';

  // CISA KEV Display
  let cisaStatus = 'Unavailable';
  let cisaSub = 'Query Failed';
  let cisaDirective = 'Catalog query encountered an upstream error';

  if (cisa.status === 'LISTED') {
    cisaStatus = 'Listed';
    cisaSub = cisa.known_ransomware_campaign_use === 'Known' ? 'Known Ransomware' : 'Active In-Wild';
    cisaDirective = cisa.due_date ? `Action Required by ${cisa.due_date}` : 'Binding Operational Directive 22-01';
  } else if (cisa.status === 'NOT_LISTED') {
    cisaStatus = 'Not Listed';
    cisaSub = 'Absence ≠ Safe';
    cisaDirective = 'Not cataloged in CISA KEV (Absence does not imply safety)';
  }

  // EPSS Display
  const epssProb =
    norm?.epss_probability !== null && norm?.epss_probability !== undefined
      ? `${(norm.epss_probability * 100).toFixed(1)}%`
      : 'N/A';
  const epssPercentile =
    norm?.epss_percentile !== null && norm?.epss_percentile !== undefined
      ? (norm.epss_percentile >= 0.99
          ? `${(norm.epss_percentile * 100).toFixed(1)}th Percentile`
          : `${Math.round(norm.epss_percentile * 100)}th Percentile`)
      : 'Unscored';
  const epssNote = epss.score_date
    ? `FIRST.org v3 (Score Date: ${epss.score_date})`
    : 'Empirical 30-day weaponization estimate';

  // Deterministic Priority Categorization (Phase 2.5 baseline)
  let priorityBadge = 'Priority 3: Standard Vulnerability Maintenance';
  let priorityColor = 'text-amber-400';
  let priorityContainerColor = 'bg-amber-400/10 border-amber-400/30';

  const isKev = norm?.is_cisa_kev ?? false;
  const numCvss = norm?.cvss_score ?? 0;
  const numEpss = norm?.epss_probability ?? 0;

  if (isKev && numCvss >= 8.5) {
    priorityBadge = 'Priority 1: Immediate Mitigation Required';
    priorityColor = 'text-error';
    priorityContainerColor = 'bg-error-container/20 border-error/40';
  } else if (isKev || numCvss >= 7.0 || numEpss >= 0.2) {
    priorityBadge = 'Priority 2: Expedited Patching Cycle';
    priorityColor = 'text-tertiary-container';
    priorityContainerColor = 'bg-tertiary-container/20 border-tertiary-container/40';
  } else if (numCvss >= 4.0) {
    priorityBadge = 'Priority 3: Standard Vulnerability Maintenance';
    priorityColor = 'text-amber-400';
    priorityContainerColor = 'bg-amber-400/10 border-amber-400/30';
  } else {
    priorityBadge = 'Priority 4: Low Priority / Informational';
    priorityColor = 'text-secondary';
    priorityContainerColor = 'bg-secondary/10 border-secondary/30';
  }

  // Rationale
  const rationaleParts: string[] = [];
  if (isKev) {
    rationaleParts.push(`Confirmed presence in CISA KEV indicates observed in-wild exploitation.`);
  } else if (cisa.status === 'NOT_LISTED') {
    rationaleParts.push(`Currently unlisted in CISA KEV (note: catalog absence is not proof of safety).`);
  }
  if (norm?.cvss_score) {
    rationaleParts.push(`CVSS base severity rated at ${norm.cvss_score} (${norm.primary_severity}).`);
  }
  if (norm?.epss_probability) {
    rationaleParts.push(`EPSS model predicts ${(norm.epss_probability * 100).toFixed(2)}% probability of exploitation in next 30 days.`);
  }
  rationaleParts.push('Synthesized via Phase 2.5 deterministic baseline engine. Autonomous Strands Decider agent reserved for Phase 3.');

  const remediationSteps: RemediationStep[] = [
    {
      step: 1,
      title: isKev ? 'Immediate Remediation / Isolation' : 'Patch Deployment Assessment',
      badge: isKev ? 'Emergency Priority' : 'Standard Routine',
      badgeColor: isKev ? 'text-error font-semibold' : 'text-primary font-medium',
      description: isKev
        ? cisa.required_action || 'Apply certified vendor patch or isolate affected assets immediately.'
        : 'Review vendor release notes and schedule patch validation in staging environments.',
    },
    {
      step: 2,
      title: 'Vulnerable Asset Inventory Discovery',
      badge: `${norm?.affected_cpe_count ?? 0} CPE Signatures`,
      badgeColor: 'text-tertiary-container font-semibold',
      description: `Audit enterprise endpoints for matching CPE configurations (${norm?.affected_cpe_count ?? 0} registered upstream product criteria).`,
    },
    {
      step: 3,
      title: 'Egress Monitoring & Exploit Detection',
      badge: 'Telemetry Alerting',
      badgeColor: 'text-secondary font-semibold',
      description: 'Configure SIEM correlation rules to detect exploitation attempts and anomalous outbound connections.',
    },
  ];

  // Parse CVSS vectors for accordion breakdown
  const vectorPairs: Array<{ label: string; value: string }> = [];
  if (norm?.cvss_vector) {
    const parts = norm.cvss_vector.split('/');
    for (const p of parts) {
      const [k, v] = p.split(':');
      if (k && v && k !== 'CVSS') {
        vectorPairs.push({ label: k, value: v });
      }
    }
  }

  return {
    title: norm?.title || `Vulnerability ${res.cve_id}`,
    cve: res.cve_id,
    desc: norm?.description || 'Normalized threat intelligence record.',
    summary: norm?.summary || generateOperationalSummary(norm?.description, norm?.title, res.cve_id, nvd.cpe_configurations),
    technicalDescription: norm?.description || nvd.error_message || 'NVD record telemetry.',
    severity,
    severityColor: severityColors[severity],
    cvss: cvssScore,
    cvssVector,
    cisa: cisaStatus,
    cisaSub,
    cisaDirective,
    epss: epssProb,
    epssPercentile,
    epssNote,
    priorityBadge,
    priorityColor,
    priorityContainerColor,
    rationale: rationaleParts.join(' '),
    remediationSteps,
    evidence: {
      nvd: {
        abstract: norm?.description || nvd.error_message || 'NVD record telemetry.',
        evaluatedAgo: nvd.last_modified_date ? new Date(nvd.last_modified_date).toLocaleDateString() : (nvd.published_date ? new Date(nvd.published_date).toLocaleDateString() : 'N/A'),
        publishedDate: nvd.published_date ? new Date(nvd.published_date).toLocaleDateString() : 'N/A',
        lastModifiedDate: nvd.last_modified_date ? new Date(nvd.last_modified_date).toLocaleDateString() : 'N/A',
        evaluatedAt: res.retrieved_at ? new Date(res.retrieved_at).toLocaleString() : 'Live',
        vectors: vectorPairs.length > 0 ? vectorPairs : [{ label: 'CVSS', value: norm?.cvss_score ? norm.cvss_score.toFixed(1) : 'N/A' }],
        cpe: (nvd.cpe_configurations || []).join('\n') || (norm?.affected_cpe_count ? `${norm.affected_cpe_count} affected product CPE configurations indexed.` : 'No CPE signatures published.'),
      },
      cisa: {
        listedDate: cisa.date_added || (cisa.status === 'NOT_LISTED' ? 'Not in KEV' : 'Unavailable'),
        exploitationStatus: cisa.status === 'LISTED' ? 'Known Exploited' : (cisa.status === 'NOT_LISTED' ? 'Not In KEV' : 'Query Failed'),
        exploitationDesc: cisa.notes,
        ransomwareStatus: cisa.known_ransomware_campaign_use || (cisa.status === 'NOT_LISTED' ? 'No KEV Record' : 'Unknown'),
        ransomwareDesc: cisa.status === 'LISTED' ? 'Reported in known ransomware or threat campaigns.' : 'No confirmed ransomware campaigns registered in KEV.',
        enforcementDeadline: cisa.due_date || (cisa.status === 'NOT_LISTED' ? 'N/A (Unlisted)' : 'Unavailable'),
        actionRequirement: cisa.required_action || (cisa.status === 'NOT_LISTED' ? 'Follow organizational baseline security patching guidance.' : 'Catalog data unavailable.'),
      },
      epss: {
        probability: epssProb,
        percentile: epssPercentile,
        percentileSub: norm?.epss_percentile ? `Top ${(100 - norm.epss_percentile * 100).toFixed(1)}% of scored CVEs` : 'Unscored',
        interpretiveNote: epss.interpretive_note,
      },
    },
    // Metadata
    isLive: true,
    overallStatus: res.status,
    provenance: res.provenance,
    sourceStatuses: {
      nvd: nvd.status,
      cisa: cisa.status,
      epss: epss.status,
    },
    retrievalTimestamps: {
      nvd: nvd.retrieved_at,
      cisa: cisa.retrieved_at,
      epss: epss.retrieved_at,
      overall: res.retrieved_at,
    },
    errors: res.errors,
  };
}

/**
 * Helper to map backend TriageApiResponse (with Bedrock / Strands Decider decision) into frontend CveData model.
 */
export function mapTriageToCveData(res: TriageApiResponse): CveData {
  if (!res.decision) {
    return mapBackendToCveData(res);
  }
  // Base normalization
  const baseData = mapBackendToCveData(res);
  const decision = res.decision;

  let priorityBadge = 'Priority 3: Standard Vulnerability Maintenance';
  let priorityColor = 'text-amber-400';
  let priorityContainerColor = 'bg-amber-400/10 border-amber-400/30';

  switch (decision.priority) {
    case 'Critical':
      priorityBadge = 'Priority 1: Immediate Mitigation Required';
      priorityColor = 'text-error';
      priorityContainerColor = 'bg-error-container/20 border-error/40';
      break;
    case 'High':
      priorityBadge = 'Priority 2: Expedited Patching Cycle';
      priorityColor = 'text-tertiary-container';
      priorityContainerColor = 'bg-tertiary-container/20 border-tertiary-container/40';
      break;
    case 'Medium':
      priorityBadge = 'Priority 3: Standard Vulnerability Maintenance';
      priorityColor = 'text-amber-400';
      priorityContainerColor = 'bg-amber-400/10 border-amber-400/30';
      break;
    case 'Low':
      priorityBadge = 'Priority 4: Low Priority / Informational';
      priorityColor = 'text-secondary';
      priorityContainerColor = 'bg-secondary/10 border-secondary/30';
      break;
  }

  const deciderStatus = decision.decider_status ?? (decision as any).deciderStatus;
  const bedrockStatus = decision.bedrock_status ?? (decision as any).bedrockStatus;
  const rawFallbackReason = decision.fallback_reason ?? (decision as any).fallbackReason ?? null;

  // Resolve engine truthfully based on decision property, top-level response, and stage statuses
  let engine = decision.engine || (res as any).engine;
  if (!engine) {
    if (deciderStatus === 'success' && bedrockStatus === 'success') {
      engine = 'dual-ai';
    } else if (deciderStatus === 'success') {
      engine = 'decider-only';
    } else if (bedrockStatus === 'success') {
      engine = 'bedrock-only';
    } else if (rawFallbackReason) {
      engine = 'baseline';
    }
  }

  // When both AI stages succeed, fallback is not active
  const fallbackReason = (deciderStatus === 'success' && bedrockStatus === 'success') ? null : rawFallbackReason;

  // Inject AI recommended action into Step 1 of remediation steps
  const isAiEngine = engine === 'dual-ai' || engine === 'ai' || engine === 'decider-only' || engine === 'bedrock-only';
  const updatedRemediationSteps: RemediationStep[] = [
    {
      step: 1,
      title: decision.priority === 'Critical' ? 'Immediate Remediation / Isolation' : 'Recommended Next Action',
      badge: isAiEngine ? 'AI Planned' : (decision.priority === 'Critical' ? 'Emergency' : 'Standard Routine'),
      badgeColor: decision.priority === 'Critical' ? 'text-error font-semibold' : 'text-primary font-medium',
      description: decision.recommended_action || baseData.remediationSteps[0].description,
    },
    ...baseData.remediationSteps.slice(1),
  ];

  return {
    ...baseData,
    priorityBadge,
    priorityColor,
    priorityContainerColor,
    rationale: decision.rationale,
    remediationSteps: updatedRemediationSteps,
    decision,
    engine,
    confidence: decision.confidence,
    confidenceExplanation: decision.confidence_explanation ?? (decision as any).confidenceExplanation,
    confidenceIsCalibrated: decision.confidence_is_calibrated ?? (decision as any).confidenceIsCalibrated,
    recommendationSource: decision.recommendation_source ?? (decision as any).recommendationSource,
    recommendationUrl: decision.recommendation_url ?? (decision as any).recommendationUrl,
    recommendationIsVerified: decision.recommendation_is_verified ?? (decision as any).recommendationIsVerified,
    authoritativeDirective: decision.authoritative_directive ?? (decision as any).authoritativeDirective,
    authoritativeDirectiveSource: decision.authoritative_directive_source ?? (decision as any).authoritativeDirectiveSource,
    authoritativeDirectiveUrl: decision.authoritative_directive_url ?? (decision as any).authoritativeDirectiveUrl,
    riskFactors: decision.risk_factors ?? (decision as any).riskFactors ?? [],
    evidenceLimitations: decision.evidence_limitations ?? (decision as any).evidenceLimitations ?? [],
    modelId: decision.model_id ?? (decision as any).modelId,
    deciderModelId: decision.decider_model_id ?? (decision as any).deciderModelId,
    bedrockModelId: decision.bedrock_model_id ?? (decision as any).bedrockModelId,
    deciderStatus,
    bedrockStatus,
    fallbackReason,
    riskValidation: decision.risk_validation || res.risk_validation || (decision as any).riskValidation || (res as any).riskValidation || null,
  };
}

/**
 * Fetch durable triage analysis history records and KPI metrics from the backend.
 */
export async function fetchAnalysisHistory(params?: {
  search?: string;
  priority?: string;
  cisa_kev?: string;
  limit?: number;
  offset?: number;
  signal?: AbortSignal;
}): Promise<HistoryListResponse> {
  const queryParams = new URLSearchParams();
  if (params?.search) queryParams.set('search', params.search);
  if (params?.priority && params.priority !== 'ALL') queryParams.set('priority', params.priority);
  if (params?.cisa_kev && params.cisa_kev !== 'ALL') queryParams.set('cisa_kev', params.cisa_kev);
  if (params?.limit) queryParams.set('limit', String(params.limit));
  if (params?.offset) queryParams.set('offset', String(params.offset));

  const qs = queryParams.toString();
  const url = getApiUrl(`/api/history${qs ? `?${qs}` : ''}`);

  try {
    const response = await fetch(url, {
      signal: params?.signal,
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      throw new ApiError(`Failed to fetch analysis history: HTTP ${response.status}`, {
        status: response.status,
      });
    }

    return (await response.json()) as HistoryListResponse;
  } catch (err: unknown) {
    if (err instanceof ApiError) throw err;
    if (err instanceof Error && (err.name === 'AbortError' || params?.signal?.aborted)) {
      throw new ApiError('History request was aborted.', { isAborted: true });
    }
    throw new ApiError('Backend service is offline or unreachable.', { isOffline: true });
  }
}

/**
 * Fetch a specific stored analysis record (including raw TriageApiResponse) without re-running models.
 */
export async function fetchHistoryRecord(
  idOrCve: string,
  options?: { signal?: AbortSignal }
): Promise<HistoryDetailResponse> {
  const url = getApiUrl(`/api/history/${encodeURIComponent(idOrCve.trim())}`);

  try {
    const response = await fetch(url, {
      signal: options?.signal,
      headers: { Accept: 'application/json' },
    });

    if (response.status === 404) {
      throw new ApiError(`History record '${idOrCve}' not found.`, { status: 404 });
    }

    if (!response.ok) {
      throw new ApiError(`Failed to fetch history record: HTTP ${response.status}`, {
        status: response.status,
      });
    }

    return (await response.json()) as HistoryDetailResponse;
  } catch (err: unknown) {
    if (err instanceof ApiError) throw err;
    if (err instanceof Error && (err.name === 'AbortError' || options?.signal?.aborted)) {
      throw new ApiError('History record request was aborted.', { isAborted: true });
    }
    throw new ApiError('Backend service is offline or unreachable.', { isOffline: true });
  }
}

/**
 * Trigger live telemetry resynchronization across CISA KEV, NVD API 2.0, and EPSS.
 */
export async function resyncTelemetry(options?: { signal?: AbortSignal }): Promise<TelemetryResyncResponse> {
  const url = getApiUrl('/api/telemetry/resync');

  try {
    const response = await fetch(url, {
      method: 'POST',
      signal: options?.signal,
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new ApiError(data.detail || `Telemetry resync failed: HTTP ${response.status}`, {
        status: response.status,
      });
    }

    return (await response.json()) as TelemetryResyncResponse;
  } catch (err: unknown) {
    if (err instanceof ApiError) throw err;
    if (err instanceof Error && (err.name === 'AbortError' || options?.signal?.aborted)) {
      throw new ApiError('Telemetry resync request was aborted.', { isAborted: true });
    }
    throw new ApiError('Backend service is offline or unreachable.', { isOffline: true });
  }
}
