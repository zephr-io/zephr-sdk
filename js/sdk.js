/**
 * Zephr JavaScript SDK — public entry point.
 *
 * Provides `createSecret` and `retrieveSecret` — a complete, symmetric API
 * for zero-knowledge secret passing.  The server never sees plaintext; the
 * encryption key travels only in the URL fragment, which is never sent in
 * HTTP requests.
 *
 * Usage:
 *
 *   import { createSecret, retrieveSecret } from 'zephr';
 *
 *   // Standard mode — single link with key in URL fragment
 *   const { fullLink } = await createSecret('my-api-key-abc');
 *
 *   // Retrieve on the other end
 *   const { plaintext } = await retrieveSecret(fullLink);
 *
 *   // Split mode — URL and key delivered through separate channels
 *   const { url, key } = await createSecret('my-api-key-abc', {
 *     expiry: 60,
 *     split:  true,
 *   });
 *   const { plaintext } = await retrieveSecret({ url, key });
 *
 * Works in browsers (via bundler) and Node.js 22+.
 */

import { ValidationError, EncryptionError, ApiError, NetworkError } from './errors.js';
import { generateKey, buildKeyString, createEncryptedBlob, importKeyFromString, decryptBlob } from './sdk-crypto.js';
import { uploadSecret, fetchSecret } from './sdk-api.js';
import { generateLink } from './link.js';
import { SECRET_MAX_BYTES, VALID_EXPIRY } from './limits.js';

// Re-export error classes so callers need only one import target.
export { ZephrError, ValidationError, EncryptionError, ApiError, NetworkError } from './errors.js';

// Matches the 22-character base64url secret ID in a Zephr URL path.
// Negative lookahead prevents matching a 22-char prefix of a longer ID.
const SECRET_ID_RE_PATH = /\/secret\/([A-Za-z0-9_-]{22})(?![A-Za-z0-9_-])/;

// ---------------------------------------------------------------------------
// Input validation helpers
// ---------------------------------------------------------------------------

/**
 * Validate the secret string: type, non-empty, byte length.
 * @param {unknown} secret
 * @returns {string} The validated secret string
 * @throws {ValidationError}
 */
function validateSecret(secret) {
    if (typeof secret !== 'string') {
        throw new ValidationError('secret must be a string.');
    }
    if (secret.trim().length === 0) {
        throw new ValidationError('secret must not be empty or consist of whitespace only.');
    }
    const byteLength = new TextEncoder().encode(secret).byteLength;
    if (byteLength > SECRET_MAX_BYTES) {
        throw new ValidationError(
            `secret exceeds the maximum size of ${SECRET_MAX_BYTES} bytes (encoded: ${byteLength} bytes).`,
        );
    }
    return secret;
}

/**
 * Validate the optional hint: type, length, printable ASCII.
 * @param {unknown} hint
 * @throws {ValidationError}
 */
function validateHint(hint) {
    if (hint === undefined) return;
    if (typeof hint !== 'string') {
        throw new ValidationError('hint must be a string.');
    }
    if (hint.length === 0 || hint.length > 128) {
        throw new ValidationError('hint must be 1-128 characters.');
    }
    if (!/^[\x20-\x7E]+$/.test(hint)) {
        throw new ValidationError('hint must contain only printable ASCII characters.');
    }
}

/**
 * Safely extract options with defaults from the unknown options parameter.
 * @param {unknown} options
 * @returns {{ expiry: unknown, split: unknown, apiKey: unknown, hint: unknown, callbackUrl: unknown, callbackSecret: unknown, idempotencyKey: unknown }}
 */
function extractOptions(options) {
    const opts = options !== undefined && typeof options === 'object' && options !== null
        ? /** @type {Record<string, unknown>} */ (options)
        : {};
    return {
        expiry:         opts.expiry ?? 60,
        split:          opts.split ?? false,
        apiKey:         opts.apiKey ?? null,
        hint:           opts.hint,
        callbackUrl:    opts.callbackUrl,
        callbackSecret: opts.callbackSecret,
        idempotencyKey: opts.idempotencyKey,
    };
}

/**
 * Validate callback_url: must be a string and HTTPS.
 * @param {unknown} callbackUrl
 * @throws {ValidationError}
 */
function validateCallbackUrl(callbackUrl) {
    if (callbackUrl === undefined) return;
    if (typeof callbackUrl !== 'string') {
        throw new ValidationError('callbackUrl must be a string.');
    }
    if (callbackUrl.length > 2048) {
        throw new ValidationError('callbackUrl must not exceed 2,048 characters.');
    }
    let parsed;
    try {
        parsed = new URL(callbackUrl);
    } catch {
        throw new ValidationError('callbackUrl must be a valid URL.');
    }
    if (parsed.protocol !== 'https:') {
        throw new ValidationError('callbackUrl must use HTTPS.');
    }
    if (isPrivateHostSDK(parsed.hostname)) {
        throw new ValidationError('callbackUrl must not point to a private or reserved address.');
    }
}

/** @param {string} ip  Dotted-decimal IPv4. @returns {boolean} */
function isPrivateIPv4SDK(ip) {
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip);
    if (!m) return false;
    const [, a, b] = m.map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && (b === 0 || b === 168)) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    return a >= 224;
}

/** @param {string} ip  Bare IPv6 (no brackets). @returns {boolean} */
function isPrivateIPv6SDK(ip) {
    if (ip === '::1' || ip === '::') return true;
    if (/^fe[89a-f]/i.test(ip)) return true;
    if (ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('ff')) return true;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(ip);
    return mapped ? isPrivateIPv4SDK(mapped[1]) : false;
}

/**
 * Client-side private host precheck — no DNS resolution.
 * The server performs the authoritative DNS-level check at dispatch time.
 * @param {string} hostname
 * @returns {boolean}
 */
function isPrivateHostSDK(hostname) {
    const lower = hostname.toLowerCase();
    if (lower === 'localhost' || lower === '0.0.0.0') return true;
    if (lower.endsWith('.local') || lower.endsWith('.internal') || lower.endsWith('.localhost')) return true;
    if (lower === 'metadata.google.internal') return true;

    const bare = lower.startsWith('[') && lower.endsWith(']') ? lower.slice(1, -1) : lower;

    // Non-standard integer/hex IP representations — block outright.
    if (/^\d+$/.test(bare) || /^0x[0-9a-f]+$/i.test(bare)) return true;

    return isPrivateIPv4SDK(bare) || isPrivateIPv6SDK(bare);
}

/**
 * Validate callback_secret: required when callbackUrl is present, must be a non-empty string.
 * @param {unknown} callbackSecret
 * @param {boolean} hasCallbackUrl
 * @throws {ValidationError}
 */
function validateCallbackSecret(callbackSecret, hasCallbackUrl) {
    if (!hasCallbackUrl && callbackSecret === undefined) return;
    if (hasCallbackUrl && callbackSecret === undefined) {
        throw new ValidationError('callbackSecret is required when callbackUrl is provided.');
    }
    if (!hasCallbackUrl && callbackSecret !== undefined) {
        throw new ValidationError('callbackSecret requires callbackUrl.');
    }
    if (typeof callbackSecret !== 'string' || callbackSecret.length === 0) {
        throw new ValidationError('callbackSecret must be a non-empty string.');
    }
    if (callbackSecret.length > 256) {
        throw new ValidationError('callbackSecret must not exceed 256 characters.');
    }
}

/**
 * @param {unknown} secret
 * @param {unknown} options
 * @returns {{ secret: string, expiry: number, split: boolean, apiKey: string | null, hint: string | undefined, callbackUrl: string | undefined, callbackSecret: string | undefined, idempotencyKey: string | undefined }}
 * @throws {ValidationError}
 */
function validateInput(secret, options) {
    const validSecret = validateSecret(secret);

    const { expiry, split, apiKey, hint, callbackUrl, callbackSecret, idempotencyKey } = extractOptions(options);

    if (!VALID_EXPIRY.has(expiry)) {
        throw new ValidationError(
            `expiry must be one of: ${[...VALID_EXPIRY].join(', ')} (minutes). Sub-hour values require Dev/Pro.`,
        );
    }
    if (typeof split !== 'boolean') {
        throw new ValidationError('split must be a boolean.');
    }
    if (apiKey !== null && typeof apiKey !== 'string') {
        throw new ValidationError('apiKey must be a string or null.');
    }
    if (typeof apiKey === 'string' && apiKey.trim().length === 0) {
        throw new ValidationError('apiKey must not be empty. Pass null for anonymous use.');
    }

    validateHint(hint);
    validateCallbackUrl(callbackUrl);
    validateCallbackSecret(callbackSecret, callbackUrl !== undefined);

    if (idempotencyKey !== undefined) {
        if (typeof idempotencyKey !== 'string') {
            throw new ValidationError('idempotencyKey must be a string.');
        }
        if (idempotencyKey.length === 0 || idempotencyKey.length > 64) {
            throw new ValidationError('idempotencyKey must be 1-64 characters.');
        }
        if (!/^[A-Za-z0-9-]+$/.test(idempotencyKey)) {
            throw new ValidationError('idempotencyKey must contain only alphanumeric characters and hyphens.');
        }
    }

    if (apiKey === null && expiry !== 60) {
        throw new ValidationError(
            'Anonymous use is limited to 60-minute (1h) expiry — pass apiKey to unlock more options ' +
            '(free: up to 30 days, Dev/Pro: adds sub-hour). Create a free account at https://zephr.io/account',
        );
    }

    if (callbackUrl !== undefined && apiKey === null) {
        throw new ValidationError(
            'Webhook callbacks require authentication — pass apiKey to use callbackUrl. ' +
            'Create a free account at https://zephr.io/account',
        );
    }

    return {
        secret:         validSecret,
        expiry:         /** @type {number} */ (expiry),
        split:          /** @type {boolean} */ (split),
        apiKey:         /** @type {string | null} */ (apiKey),
        hint:           /** @type {string | undefined} */ (hint),
        callbackUrl:    /** @type {string | undefined} */ (callbackUrl),
        callbackSecret: /** @type {string | undefined} */ (callbackSecret),
        idempotencyKey: /** @type {string | undefined} */ (idempotencyKey),
    };
}

/**
 * @param {string} link
 * @returns {{ pathname: string, keyString: string }}
 * @throws {ValidationError}
 */
function parseStringLink(link) {
    let parsed;
    try {
        parsed = new URL(link);
    } catch {
        throw new ValidationError(
            'link must be a valid URL containing /secret/<id>#v1.<key>.',
        );
    }
    if (!parsed.hash) {
        throw new ValidationError(
            'link must include an encryption key in the URL fragment (after #).',
        );
    }
    return { pathname: parsed.pathname, keyString: parsed.hash.slice(1) };
}

/**
 * @param {Record<string, unknown>} input
 * @returns {{ pathname: string, keyString: string }}
 * @throws {ValidationError}
 */
function parseObjectLink(input) {
    const { url, key } = input;
    if (typeof url !== 'string') {
        throw new ValidationError('options.url must be a string.');
    }
    if (typeof key !== 'string') {
        throw new ValidationError('options.key must be a string.');
    }
    let parsed;
    try {
        parsed = new URL(url);
    } catch {
        throw new ValidationError('options.url must be a valid URL.');
    }
    return { pathname: parsed.pathname, keyString: key };
}

/**
 * Parse a shareable link (standard or split) into its secret ID and key string.
 *
 * Accepts:
 *   - A full link string: "https://zephr.io/secret/{id}#v1.{key}"
 *   - A split object:     { url: "https://zephr.io/secret/{id}", key: "v1.{key}" }
 *
 * @param {unknown} input
 * @returns {{ secretId: string, keyString: string }}
 * @throws {ValidationError}
 */
function parseRetrieveInput(input) {
    let pathname, keyString;

    if (typeof input === 'string') {
        ({ pathname, keyString } = parseStringLink(input));
    } else if (input !== null && typeof input === 'object') {
        ({ pathname, keyString } = parseObjectLink(/** @type {Record<string, unknown>} */ (input)));
    } else {
        throw new ValidationError(
            'retrieveSecret expects a link string or a { url, key } object.',
        );
    }

    // Match against pathname only — immune to query params, tracking pixels,
    // or anything else that might appear in the full URL string.
    const idMatch = SECRET_ID_RE_PATH.exec(pathname);
    if (!idMatch) {
        throw new ValidationError(
            'Cannot parse a valid secret ID from the URL. ' +
            'Expected a Zephr link containing /secret/<22-character base64url id>.',
        );
    }

    if (keyString.length === 0) {
        throw new ValidationError('Encryption key is missing.');
    }

    return { secretId: idMatch[1], keyString };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Encrypt a secret locally and upload the ciphertext to Zephr.
 *
 * Encryption uses AES-GCM-256 with a cryptographically random 256-bit key
 * and a unique 96-bit IV.  The key is embedded in the returned link's URL
 * fragment and is never transmitted to the server.
 *
 * The returned link is one-time: the server permanently destroys the record
 * on first retrieval.
 *
 * @param {string} secret
 *   The plaintext secret to encrypt.  The exact string is encrypted and
 *   returned to the recipient unchanged — no normalisation is applied.
 *   Empty strings and strings consisting entirely of whitespace are rejected.
 *   Maximum 2,048 UTF-8 bytes (equivalent to 2,048 ASCII characters; fewer
 *   for multi-byte Unicode).
 *
 * @param {object}        [options]
 * @param {5|15|30|60|1440|10080|43200}  [options.expiry=60]
 *   How long the secret remains available, in minutes.  Defaults to 60 (1 hour).
 *   Sub-hour values (5, 15, 30) require a Dev or Pro API key.
 * @param {boolean}       [options.split=false]
 *   When true, returns the URL and key as separate fields so they can be
 *   delivered through independent channels.
 * @param {string | null} [options.apiKey=null]
 *   Bearer token for authenticated requests.  Pass null (default) for
 *   anonymous use within the free-tier limits.
 * @param {string}        [options.hint]
 *   Optional plaintext label (1-128 printable ASCII chars). Stored alongside
 *   the ciphertext and returned on retrieval. Useful for agent routing,
 *   audit logs, and dashboards. Treat as non-secret.
 * @param {string}        [options.callbackUrl]
 *   HTTPS URL to receive a signed webhook event when the secret is consumed.
 *   The event is POSTed as JSON with an `X-Zephr-Signature` HMAC-SHA256 header.
 *   Requires `callbackSecret`.  Max 2,048 characters.
 * @param {string}        [options.callbackSecret]
 *   HMAC-SHA256 signing secret for the webhook callback.  Required when
 *   `callbackUrl` is set.  Max 256 characters.
 * @param {string}        [options.idempotencyKey]
 *   Caller-generated idempotency key (1-64 alphanumeric + hyphens).
 *   When omitted, the SDK auto-generates a UUID per request.
 *   Pass your own key for application-level retry safety.
 *
 * @returns {Promise<import('./types.d.ts').SecretLink>}
 *
 * @throws {ValidationError}   Invalid input.
 * @throws {EncryptionError}   Cryptographic failure.
 * @throws {ApiError}          Server returned an error response.
 * @throws {NetworkError}      Transport-level failure.
 */
export async function createSecret(secret, options) {
    const params = validateInput(secret, options);

    // Sensitive buffers declared outside try so finally can zero them
    // regardless of where execution exits.
    let plaintextBytes = null;
    let keyBytes       = null;

    try {
        plaintextBytes = new TextEncoder().encode(params.secret);

        let cryptoKey;
        ({ keyBytes, cryptoKey } = await generateKey());

        const keyString     = buildKeyString(keyBytes);
        const encryptedBlob = await createEncryptedBlob(plaintextBytes, cryptoKey);

        // Use caller-provided idempotency key, or auto-generate one.
        // Auto-generation ensures retries are safe at the HTTP level without
        // requiring the caller to think about it.  Advanced callers doing
        // application-level retry can pass their own key.
        const idempotencyKey = params.idempotencyKey ?? globalThis.crypto.randomUUID();

        const { id, expiresAt } = await uploadSecret(
            encryptedBlob,
            params.expiry,
            params.split,
            params.hint,
            params.apiKey,
            {
                callbackUrl:    params.callbackUrl,
                callbackSecret: params.callbackSecret,
                idempotencyKey,
            },
        );

        const link = generateLink(id, keyString, params.split);

        return {
            mode:      link.mode,
            fullLink:  link.fullLink,
            url:       link.url,
            key:       link.key,
            expiresAt,
            secretId:  id,
        };
    } catch (err) {
        // Re-throw typed SDK errors as-is; wrap unexpected errors.
        if (
            err instanceof ValidationError ||
            err instanceof EncryptionError  ||
            err instanceof ApiError         ||
            err instanceof NetworkError
        ) {
            throw err;
        }
        throw new EncryptionError('An unexpected error occurred during secret creation.', err);
    } finally {
        // Best-effort memory sanitisation.  JavaScript strings are immutable
        // and may be interned, so we can only zero the derived byte arrays.
        if (plaintextBytes !== null) {
            plaintextBytes.fill(0x00);
            plaintextBytes.fill(0xff);
            plaintextBytes.fill(0x00);
        }
        if (keyBytes !== null) {
            keyBytes.fill(0x00);
            keyBytes.fill(0xff);
            keyBytes.fill(0x00);
        }
    }
}

/**
 * Retrieve and decrypt a one-time secret from Zephr.
 *
 * This operation is atomic and exactly-once: the server permanently destroys
 * the record the moment it is read.  A second call with the same link returns
 * an ApiError with statusCode 410.
 *
 * The decryption key is parsed from the link and imported as a non-extractable
 * CryptoKey — the raw key bytes are zeroed immediately after import and cannot
 * be read back by any code.
 *
 * @param {string | { url: string, key: string }} link
 *   Standard mode: the full shareable URL including the key in the fragment
 *   (e.g. "https://zephr.io/secret/Ht7kR2...#v1.key...").
 *   Split mode: a { url, key } object with the two components delivered
 *   through separate channels.
 *
 * @param {object}        [options]
 * @param {string | null} [options.apiKey=null]
 *   Bearer token for authenticated requests.  Pass null (default) for
 *   anonymous use within the free-tier limits.
 *
 * @returns {Promise<import('./types.d.ts').RetrievalResult>}
 *   Structured result containing the decrypted plaintext and server metadata.
 *
 * @throws {ValidationError}   Invalid link format or key string.
 * @throws {EncryptionError}   Key import or decryption failed.
 * @throws {ApiError}          404 (not found/expired), 410 (consumed), 429 (rate limited).
 * @throws {NetworkError}      Transport-level failure.
 */
export async function retrieveSecret(link, options) {
    const { secretId, keyString } = parseRetrieveInput(link);

    const {
        apiKey = null,
    } = options !== undefined && typeof options === 'object' && options !== null
        ? /** @type {Record<string, unknown>} */ (options)
        : {};

    if (apiKey !== null && typeof apiKey !== 'string') {
        throw new ValidationError('apiKey must be a string or null.');
    }
    if (typeof apiKey === 'string' && apiKey.trim().length === 0) {
        throw new ValidationError('apiKey must not be empty. Pass null for anonymous use.');
    }

    try {
        const response      = await fetchSecret(secretId, apiKey);
        const cryptoKey     = await importKeyFromString(keyString);
        const plaintext     = await decryptBlob(response.encryptedBlob, cryptoKey);
        return {
            plaintext,
            hint:    response.hint,
            purgeAt: response.purgeAt,
        };
    } catch (err) {
        // Re-throw typed SDK errors as-is; wrap unexpected errors.
        if (
            err instanceof ValidationError ||
            err instanceof EncryptionError  ||
            err instanceof ApiError         ||
            err instanceof NetworkError
        ) {
            throw err;
        }
        throw new EncryptionError('An unexpected error occurred during secret retrieval.', err);
    }
    // Memory note: the decryption key is imported as non-extractable, so there
    // are no raw key bytes to zero here.  importKeyFromString zeroes its own
    // keyBytes in a finally block.  IV and ciphertext arrays are zeroed inside
    // decryptBlob's finally block.
}
