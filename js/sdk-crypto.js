/**
 * Isomorphic cryptography module for the Zephr SDK.
 *
 * Uses the Web Crypto API (globalThis.crypto.subtle) exclusively, which is
 * available in all modern browsers and Node.js 20+. No Node.js-specific
 * imports — this module is safe to bundle for browser environments.
 *
 * Encryption format (wire-compatible with the CLI and Python SDK):
 *
 *   1. Generate a 256-bit AES-GCM key
 *   2. Generate a random 96-bit (12-byte) IV per encryption
 *   3. Encrypt plaintext bytes → {iv: Uint8Array, ciphertext: Uint8Array}
 *   4. Base64url-encode both fields (RFC 4648 §5, no padding)
 *   5. JSON-encode: {"iv":"<base64url>","ciphertext":"<base64url>"}
 *   6. Base64url-encode the JSON string → encrypted_blob
 *
 * Key format (versioned, forward-compatible):
 *
 *   "v1.<base64url-of-32-raw-key-bytes>"
 */

import { EncryptionError } from './errors.js';

const ALGORITHM  = 'AES-GCM';
const KEY_LENGTH = 256;       // bits
const KEY_BYTES  = 32;        // KEY_LENGTH / 8
const IV_LENGTH  = 12;        // bytes (96 bits — NIST SP 800-38D §8.2)

// Key versioning constants.
// KEY_STRING_LENGTH: base64url(32 bytes) = ceil(32 * 4 / 3) = 43 chars (no padding).
// To add a new version: add it to SUPPORTED_KEY_VERSIONS and update importKeyFromString
// to handle version-specific key lengths.
const KEY_VERSION        = 'v1';
const KEY_STRING_LENGTH  = 43;
const SUPPORTED_KEY_VERSIONS = new Set(['v1']);

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Encode raw bytes to RFC 4648 §5 base64url without padding.
 * Uses chunked String.fromCharCode to handle large arrays without stack
 * overflow.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function base64urlEncode(bytes) {
    const CHUNK = 8192;
    let binary = '';
    for (let i = 0; i < bytes.length; i += CHUNK) {
        binary += String.fromCodePoint(...bytes.subarray(i, i + CHUNK));
    }
    return btoa(binary)
        .replaceAll('+', '-')
        .replaceAll('/', '_')
        .replaceAll('=', '');
}

/**
 * Decode a RFC 4648 §5 base64url string (no padding) to a Uint8Array.
 *
 * @param {string} str
 * @returns {Uint8Array}
 */
function base64urlDecode(str) {
    // Restore standard base64: swap URL-safe chars back and add padding.
    let base64 = str.replaceAll('-', '+').replaceAll('_', '/');
    while (base64.length % 4 !== 0) base64 += '=';
    const binary = atob(base64);
    const bytes  = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.codePointAt(i);
    }
    return bytes;
}

/**
 * Perform a 3-pass overwrite of a Uint8Array to reduce the window during
 * which sensitive data is readable in memory.  This is best-effort: the
 * JavaScript engine may have already copied the data internally.
 *
 * @param {Uint8Array} buf
 */
function zeroBytes(buf) {
    buf.fill(0x00);
    buf.fill(0xff);
    buf.fill(0x00);
}

// ---------------------------------------------------------------------------
// Public API — encryption
// ---------------------------------------------------------------------------

/**
 * Generate a 256-bit AES-GCM encryption key.
 *
 * Returns both the raw key bytes (for building the versioned key string to
 * embed in the shareable URL) and the CryptoKey object (for encryption).
 * The caller is responsible for zeroing `keyBytes` in a finally block after
 * use.
 *
 * @returns {Promise<{ keyBytes: Uint8Array, cryptoKey: CryptoKey }>}
 * @throws {EncryptionError}
 */
export async function generateKey() {
    let cryptoKey;
    let rawBuffer;

    try {
        // Generate as extractable so we can export the raw bytes for the URL
        // fragment.  The exported bytes are immediately embedded in the link
        // and the raw buffer is zeroed by the caller.
        cryptoKey = await globalThis.crypto.subtle.generateKey(
            { name: ALGORITHM, length: KEY_LENGTH },
            /* extractable */ true,
            ['encrypt'],
        );

        rawBuffer = await globalThis.crypto.subtle.exportKey('raw', cryptoKey);
    } catch (err) {
        throw new EncryptionError('Key generation failed.', err);
    }

    return {
        keyBytes: new Uint8Array(rawBuffer),
        cryptoKey,
    };
}

/**
 * Build the versioned key string that travels in the URL fragment.
 *
 * @param {Uint8Array} keyBytes  Raw 32-byte key material.
 * @returns {string}  e.g. "v1.AQIDBAUG..."
 */
export function buildKeyString(keyBytes) {
    return `${KEY_VERSION}.${base64urlEncode(keyBytes)}`;
}

/**
 * Encrypt plaintext bytes and return the encrypted blob in Zephr wire format.
 *
 * @param {Uint8Array} plaintextBytes  UTF-8–encoded secret.
 * @param {CryptoKey}  cryptoKey       AES-GCM CryptoKey from generateKey().
 * @returns {Promise<string>}  base64url-encoded JSON blob.
 * @throws {EncryptionError}
 */
export async function createEncryptedBlob(plaintextBytes, cryptoKey) {
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH));

    let ciphertextBuffer;
    try {
        ciphertextBuffer = await globalThis.crypto.subtle.encrypt(
            { name: ALGORITHM, iv },
            cryptoKey,
            plaintextBytes,
        );
    } catch (err) {
        throw new EncryptionError('Encryption failed.', err);
    }

    const ciphertext = new Uint8Array(ciphertextBuffer);

    const json = JSON.stringify({
        iv:         base64urlEncode(iv),
        ciphertext: base64urlEncode(ciphertext),
    });

    const blob = base64urlEncode(new TextEncoder().encode(json));

    // Zero intermediate buffers before returning.
    zeroBytes(ciphertext);

    return blob;
}

// ---------------------------------------------------------------------------
// Public API — decryption
// ---------------------------------------------------------------------------

/**
 * Parse a versioned key string and import it as a non-extractable AES-GCM
 * CryptoKey for decryption.
 *
 * SECURITY: The key is imported as non-extractable (`extractable: false`).
 * Once imported, no code — including this SDK — can read back the raw key
 * bytes.  The browser's cryptographic subsystem enforces this.
 *
 * @param {string} keyString  Versioned key string (e.g. "v1.AQIDBAUG...").
 * @returns {Promise<CryptoKey>}
 * @throws {EncryptionError}  Invalid format, unsupported version, or import failure.
 */
export async function importKeyFromString(keyString) {
    // Format: v<1–3 digits>.<base64url-of-key-bytes>
    // Digits are capped at 3 to reject pathologically long version strings.
    const match = /^v(\d{1,3})\.([A-Za-z0-9_-]+)$/.exec(keyString);
    if (!match) {
        throw new EncryptionError(
            'Invalid key format — expected "v<version>.<base64url>" (e.g. v1.<43 chars>).',
        );
    }

    const version = `v${match[1]}`;
    if (!SUPPORTED_KEY_VERSIONS.has(version)) {
        throw new EncryptionError(
            `Unsupported key version: ${version}. ` +
            `Supported: ${[...SUPPORTED_KEY_VERSIONS].join(', ')}.`,
        );
    }

    // Pre-decode length check: a valid v1 key is always exactly KEY_STRING_LENGTH
    // base64url characters.  Catching this before decode gives a clearer error
    // than the byte-length check that follows decoding.
    if (match[2].length !== KEY_STRING_LENGTH) {
        throw new EncryptionError(
            `Invalid key payload length: expected ${KEY_STRING_LENGTH} characters, ` +
            `got ${match[2].length}.`,
        );
    }

    let keyBytes = null;
    try {
        keyBytes = base64urlDecode(match[2]);

        if (keyBytes.length !== KEY_BYTES) {
            throw new EncryptionError(
                `Invalid key length: expected ${KEY_BYTES} bytes, got ${keyBytes.length}.`,
            );
        }

        const cryptoKey = await globalThis.crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: ALGORITHM, length: KEY_LENGTH },
            /* extractable */ false,  // SECURITY: key material cannot be read back
            ['decrypt'],
        );

        return cryptoKey;
    } catch (err) {
        if (err instanceof EncryptionError) throw err;
        throw new EncryptionError('Key import failed.', err);
    } finally {
        // Zero raw key bytes regardless of success or failure.
        if (keyBytes !== null) zeroBytes(keyBytes);
    }
}

/**
 * Decrypt an encrypted blob in Zephr wire format and return the plaintext.
 *
 * Intermediate byte arrays (IV, ciphertext) are zeroed in a finally block
 * regardless of outcome.  AES-GCM's authentication tag is verified as part
 * of decryption — if the ciphertext was tampered with or the key is wrong,
 * decryption fails completely and throws EncryptionError.
 *
 * @param {string}    encryptedBlob  base64url-encoded JSON blob from the server.
 * @param {CryptoKey} cryptoKey      Non-extractable AES-GCM key from importKeyFromString().
 * @returns {Promise<string>}  Decrypted plaintext.
 * @throws {EncryptionError}  Blob format invalid, or decryption failed.
 */
export async function decryptBlob(encryptedBlob, cryptoKey) {
    let iv         = null;
    let ciphertext = null;

    try {
        // Outer decode: base64url → JSON bytes → parse
        let jsonBytes;
        try {
            jsonBytes = base64urlDecode(encryptedBlob);
        } catch (err) {
            throw new EncryptionError('Encrypted blob decoding failed.', err);
        }

        let parsed;
        try {
            parsed = JSON.parse(new TextDecoder().decode(jsonBytes));
        } catch (err) {
            throw new EncryptionError('Encrypted blob is not valid JSON.', err);
        }

        if (
            !parsed ||
            typeof parsed.iv         !== 'string' ||
            typeof parsed.ciphertext !== 'string'
        ) {
            throw new EncryptionError(
                'Encrypted blob is missing required fields (iv, ciphertext).',
            );
        }

        // Inner decode: base64url → raw bytes
        try {
            iv         = base64urlDecode(parsed.iv);
            ciphertext = base64urlDecode(parsed.ciphertext);
        } catch (err) {
            throw new EncryptionError('Encrypted blob field decoding failed.', err);
        }

        // Validate IV length before passing to Web Crypto — AES-GCM requires
        // exactly 12 bytes (96 bits).  An explicit check here gives a clear
        // error rather than a browser-dependent generic crypto failure.
        if (iv.byteLength !== IV_LENGTH) {
            throw new EncryptionError(
                `Invalid IV length: expected ${IV_LENGTH} bytes, got ${iv.byteLength}.`,
            );
        }

        // AES-GCM decrypt — also verifies the authentication tag.
        let plaintextBuffer;
        try {
            plaintextBuffer = await globalThis.crypto.subtle.decrypt(
                { name: ALGORITHM, iv },
                cryptoKey,
                ciphertext,
            );
        } catch (err) {
            // Decryption fails when the key is wrong or the ciphertext was tampered.
            throw new EncryptionError(
                'Decryption failed — the key may be incorrect or the data may have been tampered with.',
                err,
            );
        }

        return new TextDecoder().decode(plaintextBuffer);

    } finally {
        // Zero all intermediate byte arrays, regardless of outcome.
        if (iv         !== null) zeroBytes(iv);
        if (ciphertext !== null) zeroBytes(ciphertext);
    }
}
