/**
 * WinHood Shared Optional TOTP 2FA Types & Validators (Browser-Safe)
 *
 * Strictly compatible with both browser (Vite) and Node.js runtimes.
 * Never import Node.js built-ins or server-only security modules here.
 *
 * Architecture:
 * - Unrestricted local access by default (`enabled: false`, `unlocked: true`).
 * - Zero user accounts, zero login/signup, zero passwords, zero PINs, zero OAuth,
 *   zero WebAuthn/Windows Hello, and zero RBAC restrictions.
 * - Optional RFC-6238 TOTP 2FA (6 digits, 30s) + 8 single-use recovery codes
 *   activatable and deactivatable directly by the local user.
 */

export interface OptionalTotpStatus {
  enabled: boolean;
  unlocked: boolean;
  remainingRecoveryCodes: number;
  configuredAt: string | null;
  serverTimeIso: string;
  totpPeriodSeconds: number;
}

export interface TotpSetupResponse {
  secret: string;
  otpauthUrl: string;
  qrDataUrl: string;
  recoveryCodes: string[];
  serverTimeIso: string;
  totpPeriodSeconds: number;
}

export interface TotpVerifyResponse {
  ok: boolean;
  enabled: boolean;
  unlocked: boolean;
  usedRecoveryCode?: boolean;
  remainingRecoveryCodes: number;
  unlockToken?: string;
  csrfToken?: string;
}

export function normalizeTotpDigits(raw: string): string {
  return String(raw || '').replace(/\D/g, '').slice(0, 6);
}

export function isValidTotpSixDigit(raw: string): boolean {
  return /^\d{6}$/.test(normalizeTotpDigits(raw));
}

export function normalizeRecoveryCode(raw: string): string {
  return String(raw || '').toUpperCase().replace(/[^A-F0-9]/g, '');
}

export function isValidRecoveryCodeFormat(raw: string): boolean {
  return /^[A-F0-9]{8}$/.test(normalizeRecoveryCode(raw));
}
