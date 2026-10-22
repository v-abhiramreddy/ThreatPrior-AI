export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
export type PriorityLevel = 'P1' | 'P2' | 'P3' | 'P4';
export type ViewState = 'loading' | 'empty' | 'error' | 'loaded';
export type DataMode = 'live' | 'demo' | 'ready' | 'analyzing';


export interface RemediationStep {
  step: number;
  title: string;
  badge: string;
  badgeColor: string;
  description: string;
}

export interface CveData {
  title: string;
  cve: string;
  desc: string;
  severity: SeverityLevel;
  severityColor: string;
  cvss: string;
  cvssVector: string;
  cisa: string;
  cisaSub: string;
  cisaDirective: string;
  epss: string;
  epssPercentile: string;
  epssNote: string;
  priorityBadge: string;
  priorityColor: string;
  priorityContainerColor: string;
  rationale: string;
  remediationSteps: RemediationStep[];
  evidence: {
    nvd: {
      abstract: string;
      evaluatedAgo: string;
      vectors: Array<{ label: string; value: string }>;
      cpe: string;
    };
    cisa: {
      listedDate: string;
      exploitationStatus: string;
      exploitationDesc: string;
      ransomwareStatus: string;
      ransomwareDesc: string;
      enforcementDeadline: string;
      actionRequirement: string;
    };
    epss: {
      probability: string;
      percentile: string;
      percentileSub: string;
      interpretiveNote: string;
    };
  };
  // Optional provenance and live telemetry metadata
  isLive?: boolean;
  overallStatus?: OverallStatus;
  provenance?: BackendProvenance;
  decision?: TriageDecision;
  engine?: DecisionEngineType;
  confidence?: number;
  confidenceExplanation?: string;
  riskFactors?: string[];
  evidenceLimitations?: string[];
  modelId?: string | null;
  deciderModelId?: string | null;
  bedrockModelId?: string | null;
  deciderStatus?: string;
  bedrockStatus?: string;
  confidenceIsCalibrated?: boolean;
  recommendationSource?: string;
  recommendationUrl?: string | null;
  recommendationIsVerified?: boolean;
  authoritativeDirective?: string | null;
  authoritativeDirectiveSource?: string | null;
  authoritativeDirectiveUrl?: string | null;
  fallbackReason?: string | null;
  riskValidation?: RiskValidationResult | null;
  sourceStatuses?: {
    nvd: SourceStatus;
    cisa: SourceStatus;
    epss: SourceStatus;
  };
  retrievalTimestamps?: {
    nvd?: string;
    cisa?: string;
    epss?: string;
    overall: string;
  };
  errors?: string[];
}

export type SourceStatus = 'AVAILABLE' | 'NOT_FOUND' | 'NOT_LISTED' | 'LISTED' | 'RATE_LIMITED' | 'FAILED' | 'TIMEOUT';
export type OverallStatus = 'OK' | 'PARTIAL' | 'NOT_FOUND' | 'ERROR';

export interface BackendCvssMetrics {
  base_score: number;
  severity: SeverityLevel;
  vector_string: string;
  exploitability_score?: number | null;
  impact_score?: number | null;
}

export interface BackendNvdProvenance {
  source: string;
  retrieved_at?: string;
  status: SourceStatus;
  vuln_status?: string;
  published_date?: string;
  last_modified_date?: string;
  cvss_v31?: BackendCvssMetrics;
  cvss_v30?: BackendCvssMetrics;
  cvss_v20?: BackendCvssMetrics;
  weaknesses: string[];
  cpe_configurations: string[];
  error_message?: string | null;
}

export interface BackendCisaKevProvenance {
  source: string;
  retrieved_at?: string;
  status: SourceStatus;
  catalog_version?: string;
  is_listed: boolean;
  date_added?: string;
  vendor_project?: string;
  product?: string;
  vulnerability_name?: string;
  due_date?: string;
  required_action?: string;
  known_ransomware_campaign_use?: string;
  notes: string;
  error_message?: string | null;
}

export interface BackendEpssProvenance {
  source: string;
  retrieved_at?: string;
  status: SourceStatus;
  model_version?: string;
  probability?: number | null;
  percentile?: number | null;
  score_date?: string;
  interpretive_note: string;
  error_message?: string | null;
}

export interface BackendProvenance {
  nvd: BackendNvdProvenance;
  cisa_kev: BackendCisaKevProvenance;
  epss: BackendEpssProvenance;
}

export interface BackendNormalizedVulnerability {
  title: string;
  description: string;
  primary_severity: SeverityLevel;
  cvss_score?: number | null;
  cvss_version?: string | null;
  cvss_vector?: string | null;
  is_cisa_kev: boolean;
  cisa_required_action?: string | null;
  cisa_due_date?: string | null;
  epss_probability?: number | null;
  epss_percentile?: number | null;
  affected_cpe_count: number;
}

export interface VulnerabilityApiResponse {
  cve_id: string;
  status: OverallStatus;
  retrieved_at: string;
  normalized?: BackendNormalizedVulnerability | null;
  provenance: BackendProvenance;
  errors: string[];
}

export type DecisionPriority = 'Critical' | 'High' | 'Medium' | 'Low';
export type DecisionEngineType = 'dual-ai' | 'decider-only' | 'bedrock-only' | 'baseline' | 'unavailable' | 'ai';

export type RiskValidationStatus = 'aligned' | 'disagreement' | 'insufficient_evidence';

export interface RiskValidationResult {
  model_priority: DecisionPriority;
  evidence_priority: DecisionPriority | null;
  risk_validation_status: RiskValidationStatus;
  risk_factors: string[];
  validation_rules_version: string;
  validation_explanation: string;
}

export interface TriageDecision {
  priority: DecisionPriority;
  rationale: string;
  risk_factors: string[];
  recommended_action: string;
  recommendation_source?: string;
  recommendation_url?: string | null;
  recommendation_is_verified?: boolean;
  authoritative_directive?: string | null;
  authoritative_directive_source?: string | null;
  authoritative_directive_url?: string | null;
  confidence: number;
  confidence_is_calibrated?: boolean;
  confidence_explanation: string;
  evidence_limitations: string[];
  engine: DecisionEngineType;
  decider_model_id?: string | null;
  bedrock_model_id?: string | null;
  decider_status?: 'success' | 'failed' | 'unavailable' | 'skipped' | 'not_invoked';
  bedrock_status?: 'success' | 'failed' | 'unavailable' | 'skipped' | 'not_invoked';
  model_id?: string | null;
  decided_at: string;
  fallback_reason?: string | null;
  risk_validation?: RiskValidationResult | null;
}

export interface TriageApiResponse {
  cve_id: string;
  status: OverallStatus;
  retrieved_at: string;
  decision: TriageDecision;
  risk_validation?: RiskValidationResult | null;
  normalized?: BackendNormalizedVulnerability | null;
  provenance: BackendProvenance;
  errors: string[];
}

export interface AuditRecord {
  id: string;
  cve: string;
  title: string;
  analyzedAt: string;
  analyzedAtIso?: string;
  analyzedBy: string;
  priority: PriorityLevel;
  priorityName?: string;
  cvss: string;
  epss: string;
  cisaKev: 'YES' | 'NO';
  mitigationStatus: string;
  mitigationColor: string;
  engine?: string;
  deciderStatus?: string;
  bedrockStatus?: string;
  isLive?: boolean;
}

export interface HistoryListResponse {
  items: AuditRecord[];
  total_count: number;
  queue_count: number;
  critical_count: number;
  kev_count: number;
}

export interface HistoryDetailResponse {
  summary: AuditRecord;
  triage_response: TriageApiResponse | null;
}

export interface TelemetrySourceDetail {
  status: string;
  message: string;
  latency_ms?: number;
  count?: number;
  source?: string;
  error?: string | null;
}

export interface TelemetryResyncResponse {
  status: 'success' | 'partial' | 'failed';
  synced_at: string;
  sources: {
    cisa_kev: TelemetrySourceDetail;
    nvd: TelemetrySourceDetail;
    epss: TelemetrySourceDetail;
  };
}

