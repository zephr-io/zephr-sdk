/**
 * Zephr SDK error hierarchy.
 *
 * All SDK errors extend ZephrError, allowing callers to catch either the base
 * class or a specific subclass depending on how granular their handling needs
 * to be.
 *
 *   ZephrError
 *   ├── ValidationError  — invalid input supplied by the caller
 *   ├── EncryptionError  — cryptographic operation failed
 *   ├── ApiError         — server returned an error response
 *   └── NetworkError     — transport-level failure (timeout, DNS, TLS, etc.)
 */

export class ZephrError extends Error {
    /**
     * @param {string} message
     * @param {ErrorOptions} [options]
     */
    constructor(message, options) {
        super(message, options);
        this.name = this.constructor.name;
    }
}

export class ValidationError extends ZephrError {
    /**
     * Raised when the caller supplies invalid input — empty secret, secret
     * exceeding the character limit, unsupported expiry value, etc.
     * @param {string} message
     * @param {unknown} [cause]
     */
    constructor(message, cause) {
        super(message, cause === undefined ? undefined : { cause });
    }
}

export class EncryptionError extends ZephrError {
    /**
     * Raised when a cryptographic operation fails — key generation, encryption,
     * or an unexpected error from the Web Crypto API.
     * @param {string} message
     * @param {unknown} [cause]
     */
    constructor(message, cause) {
        super(message, cause === undefined ? undefined : { cause });
    }
}

export class ApiError extends ZephrError {
    /**
     * Raised when the Zephr server returns a non-2xx HTTP response.
     * @param {string}        message
     * @param {number | null} statusCode  HTTP status code, or null if unavailable.
     * @param {string | null} code        Stable machine-readable error code from the
     *                                    server (e.g. 'RATE_LIMIT_EXCEEDED'), or null.
     */
    constructor(message, statusCode = null, code = null) {
        super(message);
        /** @type {number | null} */
        this.statusCode = statusCode;
        /** @type {string | null} */
        this.code = code;
    }
}

export class NetworkError extends ZephrError {
    /**
     * Raised when the request cannot be completed due to a transport-level
     * failure: timeout, DNS resolution failure, TLS error, etc.
     * @param {string} message
     * @param {unknown} [cause]
     */
    constructor(message, cause) {
        super(message, cause === undefined ? undefined : { cause });
    }
}
