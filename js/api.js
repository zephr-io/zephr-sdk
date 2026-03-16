import https from 'node:https';
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
 * @param {number} expiryHours - Hours until expiration (1, 24, 168, or 720)
 * @param {boolean} splitUrlMode - Whether to use split URL mode
 * @param {string|null} [apiKey] - Optional API key for authenticated requests
 * @returns {Promise<{id: string, expires_at: string}>}
 */
export async function uploadSecret(encryptedBlob, expiryHours, splitUrlMode, apiKey = null) {
    const url = new URL(API_URL);
    const payload = JSON.stringify({
        encrypted_blob: encryptedBlob,
        expiry_hours: expiryHours,
        split_url_mode: splitUrlMode
    });

    return new Promise((resolve, reject) => {
        const headers = {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
            'User-Agent': `zephr-cli/${CLI_VERSION}`,
        };
        if (apiKey !== null) headers['Authorization'] = `Bearer ${apiKey}`;

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
