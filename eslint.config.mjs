import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';

export default tseslint.config(
  {
    ignores: [
      'dist/**',
      'dist-desktop/**',
      'coverage/**',
      'node_modules/**',
      'release-windows/**',
      'examples/**',
      'integrations/**',
      'packages/vscode-extension/out/**',
      '.winhood_data/**',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx,js,mjs,cjs}'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.node,
        ...globals.browser,
      },
    },
    plugins: {
      'react-hooks': reactHooks,
    },
    rules: {
      // Security & unsafe-pattern guardrails (always enforced as errors)
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-script-url': 'error',
      'eqeqeq': ['error', 'always', { null: 'ignore' }],
      'no-var': 'error',
      'prefer-const': 'error',
      'no-debugger': 'error',
      'no-empty': ['error', { allowEmptyCatch: false }],
      'no-constant-condition': ['error', { checkLoops: false }],
      'no-useless-escape': 'warn',

      // React Hooks correctness
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',

      // TypeScript unused-code & maintainability checks
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-require-imports': 'warn',
      '@typescript-eslint/ban-ts-comment': [
        'error',
        {
          'ts-ignore': 'allow-with-description',
          'ts-nocheck': true,
          'ts-expect-error': 'allow-with-description',
        },
      ],
      'complexity': ['warn', 30],
    },
  },
  {
    files: ['**/*.test.{ts,tsx}', '**/*.spec.{ts,tsx}', 'scripts/**/*.{js,mjs}'],
    rules: {
      '@typescript-eslint/no-explicit-any': 'off',
      'complexity': 'off',
    },
  }
);
