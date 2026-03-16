import { webcrypto } from 'node:crypto';

const { subtle } = webcrypto;

/**
 * Crypto module - handles encryption using AES-GCM-256
 * Matches browser implementation for compatibility
 */

/**
 * Generate a 256-bit AES-GCM key
 * @returns {Promise<CryptoKey>}
 */
export async function generateKey() {
    return await subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt']
    );
}

/**
 * Export key to raw bytes
 * @param {CryptoKey} key
 * @returns {Promise<ArrayBuffer>}
 */
export async function exportKey(key) {
    return await subtle.exportKey('raw', key);
}

/**
 * Encrypt raw bytes using AES-GCM-256
 * @param {Uint8Array} data - Raw bytes to encrypt (encoding is caller's responsibility)
 * @param {CryptoKey} key
 * @returns {Promise<{iv: Uint8Array, ciphertext: Uint8Array}>}
 */
async function encrypt(data, key) {
    if (!(data instanceof Uint8Array)) {
        throw new TypeError('encrypt() requires Uint8Array — encoding must happen at the call site');
    }

    // Generate random 96-bit IV
    const iv = webcrypto.getRandomValues(new Uint8Array(12));

    const ciphertext = await subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        data
    );

    return {
        iv,
        ciphertext: new Uint8Array(ciphertext)
    };
}

/**
 * Encode bytes to base64url (RFC 4648) — used for all encoding
 * Matches browser Base64Utils.arrayToBase64Url format
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function base64urlEncode(bytes) {
    return Buffer.from(bytes).toString('base64url');
}

/**
 * Create encrypted blob in Zephr format
 * Format: base64url(JSON.stringify({iv: base64url, ciphertext: base64url}))
 * All encoding layers use base64url (RFC 4648 §5): URL-safe alphabet, no padding.
 * @param {Uint8Array} data - Raw bytes to encrypt
 * @param {CryptoKey} key
 * @returns {Promise<string>} Base64url-encoded JSON encrypted blob
 */
export async function createEncryptedBlob(data, key) {
    const { iv, ciphertext } = await encrypt(data, key);

    // base64url for IV and ciphertext (matches browser CryptoService.encrypt output)
    const ivBase64url = base64urlEncode(iv);
    const ciphertextBase64url = base64urlEncode(ciphertext);

    // 3-pass overwrite — consistent with sdk-crypto.js zeroBytes().
    ciphertext.fill(0x00);
    ciphertext.fill(0xff);
    ciphertext.fill(0x00);

    const encryptedData = {
        iv: ivBase64url,
        ciphertext: ciphertextBase64url
    };

    // Outer wrapper: base64url (matches browser Base64Utils.arrayToBase64Url output)
    const jsonString = JSON.stringify(encryptedData);
    return Buffer.from(jsonString).toString('base64url');
}

/**
 * Create versioned key string
 * @param {Uint8Array} keyBytes
 * @returns {string} Versioned key (e.g., "v1.base64url")
 */
export function createKeyString(keyBytes) {
    return `v1.${base64urlEncode(keyBytes)}`;
}
