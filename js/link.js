/**
 * Link generator - creates shareable URLs
 * Single responsibility: URL construction
 */

const BASE_URL = 'https://zephr.io';

/**
 * Generate shareable link
 * @param {string} secretId - Secret identifier from API
 * @param {string} keyString - Versioned key string
 * @param {boolean} splitUrlMode - Whether to split URL and key
 * @returns {{mode: string, url?: string, key?: string, fullLink?: string}}
 */
export function generateLink(secretId, keyString, splitUrlMode) {
    if (splitUrlMode) {
        return {
            mode: 'split',
            url: `${BASE_URL}/secret/${secretId}`,
            key: keyString
        };
    }

    return {
        mode: 'standard',
        fullLink: `${BASE_URL}/secret/${secretId}#${keyString}`
    };
}
