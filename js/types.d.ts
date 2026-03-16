/**
 * TypeScript declarations for the Zephr JavaScript SDK.
 *
 * @example
 * import { createSecret, retrieveSecret, ApiError, NetworkError } from 'zephr';
 * import type { SecretLink, CreateSecretOptions, RetrieveSecretOptions } from 'zephr';
 */

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/**
 * Options accepted by {@link createSecret}.
 */
export interface CreateSecretOptions {
    /**
     * How long the secret remains available, in hours.
     *
     * Accepted values: `1` (one hour), `24` (one day), `168` (seven days), `720` (thirty days).
     * 720 requires a Dev or Pro API key — the server returns 403 if used without one.
     *
     * @default 1
     */
    expiry?: 1 | 24 | 168 | 720;

    /**
     * When `true`, the returned object has `url` and `key` as separate
     * fields so they can be transmitted through independent channels.
     * When `false` (default), the key is embedded in the URL fragment.
     *
     * @default false
     */
    split?: boolean;

    /**
     * Bearer token for authenticated requests.  Pass `null` (default) to
     * make an anonymous request within the free-tier rate limits.
     *
     * @default null
     */
    apiKey?: string | null;
}

// ---------------------------------------------------------------------------
// Result
// ---------------------------------------------------------------------------

/**
 * The shareable link returned by {@link createSecret} in standard mode
 * (`split: false`).  The encryption key is embedded in `fullLink`'s URL
 * fragment and is never transmitted to the server.
 */
export interface StandardLink {
    mode: 'standard';
    /** Complete shareable URL including the key in the fragment. */
    fullLink: string;
    url?: undefined;
    key?: undefined;
    /** ISO 8601 timestamp indicating when the secret expires. */
    expiresAt: string;
    /** 22-character base64url secret identifier. */
    secretId: string;
}

/**
 * The shareable link returned by {@link createSecret} in split mode
 * (`split: true`).  The URL and encryption key are separated so they can
 * be delivered through different channels.
 */
export interface SplitLink {
    mode: 'split';
    fullLink?: undefined;
    /** Shareable URL without the encryption key. */
    url: string;
    /** Versioned encryption key (`v1.<base64url>`).  Transmit separately from `url`. */
    key: string;
    /** ISO 8601 timestamp indicating when the secret expires. */
    expiresAt: string;
    /** 22-character base64url secret identifier. */
    secretId: string;
}

/**
 * The object returned by {@link createSecret}.
 */
export type SecretLink = StandardLink | SplitLink;

/**
 * Options accepted by {@link retrieveSecret}.
 */
export interface RetrieveSecretOptions {
    /**
     * Bearer token for authenticated requests.  Pass `null` (default) to
     * make an anonymous request within the free-tier rate limits.
     *
     * @default null
     */
    apiKey?: string | null;
}

// ---------------------------------------------------------------------------
// Primary functions
// ---------------------------------------------------------------------------

/**
 * Encrypt a secret locally and upload the ciphertext to Zephr.
 *
 * Encryption uses AES-GCM-256 with a cryptographically random 256-bit key
 * and a unique 96-bit IV generated per invocation.  The plaintext and key
 * never leave the local environment; only the ciphertext is uploaded.
 *
 * The returned link is one-time: the server permanently destroys the record
 * on first retrieval.
 *
 * @param secret
 *   The plaintext secret to encrypt.  The exact string is encrypted and
 *   returned to the recipient unchanged — no normalisation is applied.
 *   Empty strings and strings consisting entirely of whitespace are rejected.
 *   Maximum 2,048 UTF-8 bytes (equivalent to 2,048 ASCII characters; fewer
 *   for multi-byte Unicode such as emoji or CJK characters).
 * @param options Optional configuration.
 *
 * @throws {@link ValidationError}  Invalid input.
 * @throws {@link EncryptionError}  Cryptographic failure.
 * @throws {@link ApiError}         Server returned an error response.
 * @throws {@link NetworkError}     Transport-level failure.
 *
 * @example
 * // Standard mode
 * const { fullLink } = await createSecret('sk-live-abc123');
 *
 * @example
 * // Split mode — deliver URL and key through separate channels
 * const { url, key } = await createSecret('sk-live-abc123', { split: true });
 *
 * @example
 * // 1-hour expiry with API key
 * const { fullLink } = await createSecret('temp-password', {
 *   expiry: 1,
 *   apiKey: process.env.ZEPHR_API_KEY,
 * });
 */
export declare function createSecret(
    secret: string,
    options?: CreateSecretOptions,
): Promise<SecretLink>;

/**
 * Retrieve and decrypt a one-time secret from Zephr.
 *
 * This operation is atomic and exactly-once: the server permanently destroys
 * the record the moment it is read.  A second call with the same link throws
 * an `ApiError` with `statusCode` 410 and `code` `'SECRET_ALREADY_CONSUMED'`.
 *
 * The decryption key is imported as a non-extractable `CryptoKey` and is
 * never accessible to userland code.
 *
 * @param link
 *   **Standard mode** — the full shareable URL including the key in the
 *   fragment, e.g. `"https://zephr.io/secret/Ht7kR2...#v1.key..."`.
 *
 *   **Split mode** — a `{ url, key }` object with the two components that
 *   were delivered through separate channels.
 *
 * @param options Optional configuration.
 *
 * @returns The decrypted plaintext string.
 *
 * @throws {@link ValidationError}  Invalid link format or missing key.
 * @throws {@link EncryptionError}  Key import or decryption failed.
 * @throws {@link ApiError}         404 (not found / expired), 410 (already consumed), 429 (rate limited).
 * @throws {@link NetworkError}     Transport-level failure.
 *
 * @example
 * // Standard mode — pass the full link
 * const plaintext = await retrieveSecret(fullLink);
 *
 * @example
 * // Split mode — reconstruct from separately delivered components
 * const plaintext = await retrieveSecret({ url, key });
 *
 * @example
 * // Error handling
 * try {
 *   const plaintext = await retrieveSecret(link);
 * } catch (err) {
 *   if (err instanceof ApiError && err.statusCode === 410) {
 *     console.error('Secret already consumed.');
 *   } else if (err instanceof ApiError && err.statusCode === 404) {
 *     console.error('Secret not found or expired.');
 *   } else {
 *     throw err;
 *   }
 * }
 */
export declare function retrieveSecret(
    link: string | { url: string; key: string },
    options?: RetrieveSecretOptions,
): Promise<string>;

// ---------------------------------------------------------------------------
// Error classes
// ---------------------------------------------------------------------------

/**
 * Machine-readable error codes returned by the Zephr server in the
 * `ApiError.code` property.  Safe to switch/match on — these are stable.
 *
 * @example
 * if (err instanceof ApiError) {
 *   switch (err.code) {
 *     case 'SECRET_ALREADY_CONSUMED': ...
 *     case 'MONTHLY_LIMIT_EXCEEDED':  ...
 *   }
 * }
 */
export type ApiErrorCode =
    | 'INVALID_REQUEST_BODY'
    | 'INVALID_API_KEY'
    | 'ANON_RATE_LIMIT_EXCEEDED'
    | 'UPGRADE_REQUIRED'
    | 'PAYLOAD_TOO_LARGE'
    | 'MONTHLY_LIMIT_EXCEEDED'
    | 'SECRET_NOT_FOUND'
    | 'SECRET_EXPIRED'
    | 'SECRET_ALREADY_CONSUMED';

/**
 * Base class for all Zephr SDK errors.
 * Catch this to handle any SDK error uniformly.
 */
export declare class ZephrError extends Error {
    readonly name: string;
}

/**
 * Raised when the caller supplies invalid input — empty secret, secret
 * exceeding the character limit, unsupported expiry value, etc.
 */
export declare class ValidationError extends ZephrError {
    readonly cause?: unknown;
}

/**
 * Raised when a cryptographic operation fails.
 */
export declare class EncryptionError extends ZephrError {
    readonly cause?: unknown;
}

/**
 * Raised when the Zephr server returns a non-2xx HTTP response.
 *
 * Both `statusCode` and `code` are stable and safe to branch on:
 * ```ts
 * if (err instanceof ApiError) {
 *   if (err.statusCode === 410) { /* already consumed *\/ }
 *   if (err.code === 'MONTHLY_LIMIT_EXCEEDED') { /* quota exceeded *\/ }
 * }
 * ```
 */
export declare class ApiError extends ZephrError {
    /** HTTP status code, or `null` if unavailable. */
    readonly statusCode: number | null;
    /**
     * Machine-readable error code from the server response body.
     * `null` when the server did not return a structured error envelope.
     * See {@link ApiErrorCode} for the full list of known values.
     */
    readonly code: ApiErrorCode | string | null;
}

/**
 * Raised when the request cannot be completed due to a transport-level
 * failure: timeout, DNS resolution failure, TLS error, etc.
 */
export declare class NetworkError extends ZephrError {
    readonly cause?: unknown;
}
