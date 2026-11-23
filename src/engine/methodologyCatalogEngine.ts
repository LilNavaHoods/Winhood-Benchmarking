/**
 * WinHood Methodology Catalog Engine (Backend Compatibility Re-Export Façade)
 *
 * Canonical implementation lives in `src/shared/benchmarkConfig.ts` (100% browser-safe
 * and Node.js-compatible) to ensure zero duplication between frontend Wizard and backend
 * orchestrator/API endpoints.
 */

export {
  METHODOLOGY_CATALOG_VERSION,
  ALL_12_CATEGORIES,
  DEFAULT_EQUIVALENCE_ENVIRONMENT,
  EVALUATION_CRITERIA_CATALOG,
  DOMAIN_SPECIALIZED_PROFILES,
  getProfileByIdOrDomain,
  inferSoftwareDomainKey,
  determineSourceIngestionState,
  determineSourceAvailability,
  evaluateCriteriaForSoftware,
  evaluateSoftwareComparability,
  buildPreAnalysisSummary,
  type HardwareProfile,
} from '../shared/benchmarkConfig';
