import https from 'node:https';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { SECRET_ID_RE } from './limits.js';

const require = createRequire(import.meta.url);
const CLI_VERSION = require('./package.json').version;

/**
 * API client - handles communication with Zephr server
 * Single responsibility: HTTP requests
 */

const API_URL = 'https://zephr.io/api/secrets';

/**
 * Upload encrypted secret to Zephr
 * @param {string} encryptedBlob - Base64url-encoded encrypted data
 * @param {number} expiry - Expiry in minutes (must be in ALLOWED_EXPIRY)
 * @param {boolean} splitUrlMode - Whether to use split URL mode
 * @param {string} [hint] - Optional plaintext label (non-secret, max 128 chars)
 * @param {string|null} [apiKey] - Optional API key for authenticated requests
 * @param {object} [extra] - Additional optional fields
 * @param {string} [extra.callbackUrl] - HTTPS webhook URL for lifecycle events
 * @param {string} [extra.callbackSecret] - HMAC-SHA256 signing secret for the webhook
 * @returns {Promise<{id: string, expires_at: string}>}
 */
export async function uploadSecret(encryptedBlob, expiry, splitUrlMode, hint, apiKey = null, extra = {}) {
    const url = new URL(API_URL);
    const payload = JSON.stringify({
        encrypted_blob: encryptedBlob,
        expiry,
        split_url_mode: splitUrlMode,
        ...(hint && { hint }),
        ...(extra.callbackUrl && { callback_url: extra.callbackUrl }),
        ...(extra.callbackSecret && { callback_secret: extra.callbackSecret }),
    });

    return new Promise((resolve, reject) => {
        const headers = {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
            'User-Agent': `zephr-cli/${CLI_VERSION}`,
        };
        if (apiKey !== null) headers['Authorization'] = `Bearer ${apiKey}`;

        // Auto-generate idempotency key for every create — protects against
        // infrastructure-level replays (API Gateway, proxy retries).
        headers['Idempotency-Key'] = crypto.randomUUID();

        const options = {
            hostname: url.hostname,
            port: 443,
            path: url.pathname,
            method: 'POST',
            headers
        };

        const req = https.request(options, (res) => {
            const chunks = [];
            let totalBytes = 0;

            res.on('data', (chunk) => {
                // Guard against oversized responses (1MB limit).
                // chunk.length on a Buffer is byte count — correct for multi-byte payloads.
                totalBytes += chunk.length;
                if (totalBytes > 1_000_000) {
                    req.destroy(new Error('Response too large'));
                    return;
                }
                chunks.push(chunk);
            });

            res.on('end', () => {
                const data = Buffer.concat(chunks).toString('utf8');
                if (res.statusCode === 201) {
                    try {
                        const result = JSON.parse(data);
                        validateResponse(result);
                        resolve(result);
                    } catch (err) {
                        reject(new Error(`Invalid response: ${err.message}`));
                    }
                } else {
                    // Sanitize error output — don't leak raw server response body
                    // which may contain HTML, debug info, or stack traces
                    try {
                        const error = JSON.parse(data);
                        const errObj = error.error;
                        let detail = null;
                        if (typeof errObj === 'object' && errObj !== null) detail = errObj.message ?? null;
                        else if (typeof errObj === 'string') detail = errObj;
                        reject(new Error(detail || `Request failed (HTTP ${res.statusCode})`));
                    } catch {
                        reject(new Error(`Request failed (HTTP ${res.statusCode})`));
                    }
                }
            });
        });

        req.setTimeout(10000, () => {
            // Settle the promise before destroying — if destroy() emits an
            // 'error' event synchronously, reject() must already be a no-op
            // so the error handler below doesn't overwrite the timeout message.
            reject(new Error('Request timed out (10s)'));
            req.destroy();
        });

        req.on('error', (err) => {
            reject(new Error(`Network error: ${err.message}`));
        });

        req.write(payload);
        req.end();
    });
}

/**
 * Validate API response structure — defense-in-depth against
 * malicious or compromised server injecting data into URLs
 * Matches browser ApiClient._validateResponse
 * @param {object} result
 */
function validateResponse(result) {
    if (!result || typeof result !== 'object') {
        throw new Error('Invalid server response');
    }
    if (typeof result.id !== 'string' || !SECRET_ID_RE.test(result.id)) {
        throw new Error('Invalid secret ID format from server');
    }
    if (typeof result.expires_at !== 'string' || Number.isNaN(Date.parse(result.expires_at))) {
        throw new TypeError('Invalid expiration timestamp from server');
    }
}
