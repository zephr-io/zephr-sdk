/**
 * Isomorphic HTTP client for the Zephr SDK.
 *
 * Uses the Fetch API (globalThis.fetch) — available in all modern browsers
 * and Node.js 20+.  Safe to bundle for browser environments.
 *
 * Responsibilities:
 *   - POST encrypted blob to /api/secrets
 *   - GET encrypted blob from /api/secrets/{id} (one-time, atomic)
 *   - Enforce 10-second request timeout
 *   - Guard against oversized responses (1 MB)
 *   - Validate response structure before returning
 *   - Map HTTP / transport errors to typed SDK errors, preserving server codes
 */

import { createRequire } from 'node:module';
import { ApiError, NetworkError, ValidationError } from './errors.js';
import { SECRET_ID_RE } from './limits.js';

const API_BASE           = 'https://zephr.io/api/secrets';
const TIMEOUT_MS         = 10_000;
const MAX_RESPONSE_BYTES = 1_000_000;  // 1 MB

// Read SDK version from package.json automatically so it never drifts.
// createRequire works in Node.js 20+; browser bundlers (webpack/rollup/esbuild)
// inline the require('./package.json') call and strip the node:module import.
const SDK_VERSION = createRequire(import.meta.url)('./package.json').version;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Extract the human-readable message and machine-readable code from an error
 * response body.  Returns nulls when the body cannot be parsed or the fields
 * are absent — the caller substitutes a generic fallback message.
 *
 * @param {string} body  Raw response text.
 * @returns {{ message: string | null, code: string | null }}
 */
function extractErrorInfo(body) {
    try {
        const parsed = JSON.parse(body);
        const errObj = parsed?.error;

        const message = typeof errObj === 'string' ? errObj : (errObj?.message ?? null);

        const code =
            typeof errObj?.code === 'string' ? errObj.code : null;

        return { message, code };
    } catch {
        // Non-JSON body — do not surface raw HTML or debug output.
        return { message: null, code: null };
    }
}

/**
 * Validate the structure of a successful (HTTP 201) create response.
 * Defense-in-depth: guards against a compromised or misconfigured server
 * injecting malformed data into the shareable URL.
 *
 * @param {unknown} body  Parsed JSON response body.
 * @throws {ValidationError}
 */
function validateCreateResponse(body) {
    if (!body || typeof body !== 'object') {
        throw new ValidationError('Invalid server response: expected a JSON object.');
    }

    const { id, expires_at } = /** @type {Record<string, unknown>} */ (body);

    if (typeof id !== 'string' || !SECRET_ID_RE.test(id)) {
        throw new ValidationError('Invalid server response: malformed secret ID.');
    }

    if (typeof expires_at !== 'string' || Number.isNaN(Date.parse(expires_at))) {
        throw new ValidationError('Invalid server response: malformed expiration timestamp.');
    }
}

/**
 * Read the response body with a 1 MB size cap applied at both the
 * Content-Length header and the actual body length.
 *
 * @param {Response} response
 * @returns {Promise<string>}
 * @throws {NetworkError}
 */
async function readResponseText(response) {
    const contentLength = Number.parseInt(response.headers.get('content-length') ?? '0', 10);
    if (contentLength > MAX_RESPONSE_BYTES) {
        throw new NetworkError('Server response exceeds the 1 MB size limit.');
    }

    const text = await response.text();

    // Use byte length for the body cap — consistent with how limits are applied
    // elsewhere in the codebase.  UTF-16 .length would undercount multi-byte chars.
    if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) {
        throw new NetworkError('Server response exceeds the 1 MB size limit.');
    }

    return text;
}

/**
 * Wrap a fetch rejection into a typed NetworkError.
 *
 * @param {unknown} err
 * @returns {never}
 */
function throwNetworkError(err) {
    const isTimeout = err instanceof Error && err.name === 'TimeoutError';
    if (isTimeout) {
        throw new NetworkError(`Request timed out after ${TIMEOUT_MS / 1000}s.`, err);
    }
    const detail = err instanceof Error ? err.message : JSON.stringify(err);
    throw new NetworkError(`Network error: ${detail}`, err);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Upload an encrypted blob to the Zephr API and return the server-assigned
 * secret ID and expiration timestamp.
 *
 * @param {string}          encryptedBlob  Base64url-encoded encrypted JSON blob.
 * @param {number}          expiryHours    Expiry in hours: 1, 24, 168, or 720.
 * @param {boolean}         splitUrlMode   Whether the caller intends to share URL and key separately.
 * @param {string | null}   [apiKey]       Optional Bearer token for authenticated requests.
 * @returns {Promise<{ id: string, expiresAt: string }>}
 * @throws {ApiError}        Server returned a non-201 response.
 * @throws {NetworkError}    Transport-level failure (timeout, DNS, TLS, etc.).
 * @throws {ValidationError} Server response failed structural validation.
 */
export async function uploadSecret(encryptedBlob, expiryHours, splitUrlMode, apiKey = null) {
    const headers = /** @type {Record<string, string>} */ ({
        'Content-Type': 'application/json',
        'User-Agent':   `zephr-js/${SDK_VERSION}`,
    });

    if (apiKey !== null) {
        headers['Authorization'] = `Bearer ${apiKey}`;
    }

    const body = JSON.stringify({
        encrypted_blob: encryptedBlob,
        expiry_hours:   expiryHours,
        split_url_mode: splitUrlMode,
    });

    let response;
    try {
        response = await fetch(API_BASE, {
            method:  'POST',
            headers,
            body,
            signal: AbortSignal.timeout(TIMEOUT_MS),
        });
    } catch (err) {
        throwNetworkError(err);
    }

    const text = await readResponseText(response);

    if (response.status !== 201) {
        const { message, code } = extractErrorInfo(text);
        throw new ApiError(
            message ?? `Request failed (HTTP ${response.status}).`,
            response.status,
            code,
        );
    }

    let parsed;
    try {
        parsed = JSON.parse(text);
    } catch {
        throw new ValidationError('Invalid server response: body is not valid JSON.');
    }

    validateCreateResponse(parsed);

    return {
        id:        /** @type {{ id: string, expires_at: string }} */ (parsed).id,
        expiresAt: /** @type {{ id: string, expires_at: string }} */ (parsed).expires_at,
    };
}

/**
 * Fetch the encrypted blob for a secret and consume it atomically.
 *
 * This operation is exactly-once: the server permanently destroys the record
 * the moment it is read.  A second request for the same ID returns 410 Gone
 * regardless of timing.
 *
 * @param {string}        secretId  22-character base64url secret identifier.
 * @param {string | null} [apiKey]  Optional Bearer token for authenticated requests.
 * @returns {Promise<string>}  The encrypted blob string (base64url).
 * @throws {ApiError}        404 (not found / expired), 410 (consumed), 429 (rate limited).
 * @throws {NetworkError}    Transport-level failure.
 * @throws {ValidationError} Server response failed structural validation.
 */
export async function fetchSecret(secretId, apiKey = null) {
    // Validate secretId before interpolating into the URL — defense-in-depth
    // against path traversal if this function is called outside the public API.
    if (!SECRET_ID_RE.test(secretId)) {
        throw new ValidationError('Invalid secret ID format.');
    }

    const headers = /** @type {Record<string, string>} */ ({
        'User-Agent': `zephr-js/${SDK_VERSION}`,
    });

    if (apiKey !== null) {
        headers['Authorization'] = `Bearer ${apiKey}`;
    }

    let response;
    try {
        response = await fetch(`${API_BASE}/${secretId}`, {
            method: 'GET',
            headers,
            signal: AbortSignal.timeout(TIMEOUT_MS),
        });
    } catch (err) {
        throwNetworkError(err);
    }

    const text = await readResponseText(response);

    if (response.status !== 200) {
        const { message, code } = extractErrorInfo(text);
        throw new ApiError(
            message ?? `Request failed (HTTP ${response.status}).`,
            response.status,
            code,
        );
    }

    let parsed;
    try {
        parsed = JSON.parse(text);
    } catch {
        throw new ValidationError('Invalid server response: body is not valid JSON.');
    }

    const { encrypted_blob } = /** @type {Record<string, unknown>} */ (parsed);

    if (typeof encrypted_blob !== 'string' || !/^[A-Za-z0-9_-]+$/.test(encrypted_blob)) {
        throw new ValidationError('Invalid server response: malformed encrypted blob.');
    }

    return encrypted_blob;
}
