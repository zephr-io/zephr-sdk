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
 *   const plaintext = await retrieveSecret(fullLink);
 *
 *   // Split mode — URL and key delivered through separate channels
 *   const { url, key } = await createSecret('my-api-key-abc', {
 *     expiry: 1,
 *     split:  true,
 *   });
 *   const plaintext = await retrieveSecret({ url, key });
 *
 * Works in browsers (via bundler) and Node.js 20+.
 */

import { ValidationError, EncryptionError, ApiError, NetworkError } from './errors.js';
import { generateKey, buildKeyString, createEncryptedBlob, importKeyFromString, decryptBlob } from './sdk-crypto.js';
import { uploadSecret, fetchSecret } from './sdk-api.js';
import { generateLink } from './link.js';
import { SECRET_MAX_BYTES, VALID_EXPIRY_HOURS } from './limits.js';

// Re-export error classes so callers need only one import target.
export { ZephrError, ValidationError, EncryptionError, ApiError, NetworkError } from './errors.js';

// Matches the 22-character base64url secret ID in a Zephr URL path.
// Negative lookahead prevents matching a 22-char prefix of a longer ID.
const SECRET_ID_RE_PATH = /\/secret\/([A-Za-z0-9_-]{22})(?![A-Za-z0-9_-])/;

// ---------------------------------------------------------------------------
// Input validation helpers
// ---------------------------------------------------------------------------

/**
 * @param {unknown} secret
 * @param {unknown} options
 * @returns {{ secret: string, expiry: number, split: boolean, apiKey: string | null }}
 * @throws {ValidationError}
 */
function validateInput(secret, options) {
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

    const {
        expiry = 1,
        split  = false,
        apiKey = null,
    } = options !== undefined && typeof options === 'object' && options !== null
        ? /** @type {Record<string, unknown>} */ (options)
        : {};

    if (!VALID_EXPIRY_HOURS.has(expiry)) {
        throw new ValidationError(
            `expiry must be one of: ${[...VALID_EXPIRY_HOURS].join(', ')} hours (720 requires Dev/Pro).`,
        );
    }

    if (typeof split !== 'boolean') {
        throw new ValidationError('split must be a boolean.');
    }

    if (apiKey !== null && typeof apiKey !== 'string') {
        throw new ValidationError('apiKey must be a string or null.');
    }

    if (apiKey === null && expiry > 1) {
        throw new ValidationError(
            'Anonymous use is limited to 1h expiry — pass apiKey to unlock longer expiry ' +
            '(free: up to 7 days, Dev/Pro: up to 30 days). Create a free account at https://zephr.io/account',
        );
    }

    return {
        secret,
        expiry: /** @type {number} */ (expiry),
        split:  /** @type {boolean} */ (split),
        apiKey: /** @type {string | null} */ (apiKey),
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
 * @param {1|24|168|720}  [options.expiry=1]
 *   How long the secret remains available, in hours.  Defaults to 1.
 *   24h+ requires a free account; 720 (30 days) requires a Dev or Pro API key.
 * @param {boolean}       [options.split=false]
 *   When true, returns the URL and key as separate fields so they can be
 *   delivered through independent channels.
 * @param {string | null} [options.apiKey=null]
 *   Bearer token for authenticated requests.  Pass null (default) for
 *   anonymous use within the free-tier limits.
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
        const { id, expiresAt } = await uploadSecret(
            encryptedBlob,
            params.expiry,
            params.split,
            params.apiKey,
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
 * @returns {Promise<string>}  The decrypted plaintext.
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

    try {
        const encryptedBlob = await fetchSecret(secretId, apiKey);
        const cryptoKey     = await importKeyFromString(keyString);
        const plaintext     = await decryptBlob(encryptedBlob, cryptoKey);
        return plaintext;
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
