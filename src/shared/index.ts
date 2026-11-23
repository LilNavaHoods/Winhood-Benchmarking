/**
 * WinHood Browser-Safe Shared Barrel
 *
 * All exports from `src/shared/` are guaranteed compatible with browser bundles
 * and Node.js runtimes. Verified automatically by `npm run check:browser-imports`.
 */

export {
  ALL_BENCHMARK_CATEGORIES,
  DEFAULT_CATEGORY_WEIGHTS,
  MARKET_CATEGORIES,
  type MarketCategory,
} from './benchmarkCategories';

export {
  normalizeEnabledCategoryWeights,
} from './benchmarkWeights';

export {
  validateCategoryWeights,
  validateEquivalenceConditions,
  classifyScoreScale,
  type WeightValidationResult,
  type EquivalenceValidationResult,
} from './benchmarkValidation';

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
} from './benchmarkConfig';

export {
  GITHUB_OAUTH_ERROR_MESSAGES,
  GITHUB_OAUTH_START_URL,
  GITHUB_OAUTH_UNAVAILABLE_NOTICE,
  resolveGitHubOAuthCallbackFeedback,
  resolveGitHubOAuthErrorMessage,
  extractGitHubOAuthErrorFromSearch,
  resolveGitHubOAuthCtaLabel,
  type GitHubOAuthAvailabilityState,
  type GitHubOAuthCallbackErrorCode,
  type GitHubOAuthCallbackFeedback,
  type ParsedGitHubOAuthSearchError,
  type WinHoodAccessMode,
} from './authTypes';
