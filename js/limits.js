/**
 * Shared input limits for the Zephr CLI and SDK.
 *
 * SECRET_MAX_BYTES — the enforced limit.
 *   Checked against the UTF-8 encoded byte length of the plaintext.
 *   2,048 bytes produces a ~2.8 KB encrypted blob — well within the 16 KB
 *   server limit.  For pure-ASCII secrets this is equivalent to 2,048 chars;
 *   for multi-byte Unicode the effective character count is lower.
 *   Used by cli/index.js (byte-accurate check) and cli/cli.js (streaming guard).
 *
 * SECRET_MAX_LENGTH — exported for npm package API compatibility only.
 *   The CLI itself does not use this constant; it uses SECRET_MAX_BYTES.
 *   The web interface has its own public/limits.js with separate ANON_MAX_LENGTH
 *   (1,000 code units for anonymous users) and SECRET_MAX_LENGTH (2,048 for auth).
 */
export const SECRET_MAX_BYTES   = 2048;
export const SECRET_MAX_LENGTH  = 2048;

// 128-bit entropy (16 bytes) encoded as base64url without padding = exactly 22 characters.
// Used by the SDK and CLI to validate secret IDs before interpolating into URLs.
export const SECRET_ID_RE = /^[A-Za-z0-9_-]{22}$/;

// Valid expiry values in hours — shared across SDK, CLI, and arg parser.
// Centralised here so a future tier change only requires one edit.
export const VALID_EXPIRY_HOURS = new Set([1, 24, 168, 720]);
