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
  validateCategoryWeights,
  validateEquivalenceConditions,
  classifyScoreScale,
} from './benchmarkWeights';

export {
  GITHUB_OAUTH_ERROR_MESSAGES,
  resolveGitHubOAuthErrorMessage,
  type GitHubOAuthCallbackErrorCode,
  type WinHoodAccessMode,
} from './authTypes';
