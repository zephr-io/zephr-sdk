/**
 * CLI interface - handles user input and output
 * Single responsibility: User interaction
 */

import { createRequire } from 'node:module';
import { SECRET_MAX_BYTES, VALID_EXPIRY_HOURS } from './limits.js';

const require = createRequire(import.meta.url);
const { version } = require('./package.json');

/**
 * @param {string[]} args
 * @param {number} i
 * @param {object} config
 * @returns {number} updated index
 */
function parseExpiryFlag(args, i, config) {
    if (i + 1 >= args.length) {
        throw new Error('--expiry requires a value (1, 24, 168, or 720)');
    }
    const value = Number.parseInt(args[i + 1], 10);
    if (!VALID_EXPIRY_HOURS.has(value)) {
        throw new Error(`Expiry must be one of: ${[...VALID_EXPIRY_HOURS].join(', ')} hours`);
    }
    config.expiry = value;
    return i + 1;
}

/**
 * @param {string[]} args
 * @param {number} i
 * @param {object} config
 * @returns {number} updated index
 */
function parseApiKeyFlag(args, i, config) {
    if (i + 1 >= args.length) {
        throw new Error('--api-key requires a value');
    }
    config.apiKey = args[i + 1];
    return i + 1;
}

/**
 * Parse command-line arguments
 * @param {string[]} args - Process arguments
 * @returns {{secret: string, expiry: number, split: boolean, help: boolean, version: boolean}}
 */
export function parseArgs(args) {
    const config = {
        secret: null,
        expiry: 1,
        split: false,
        apiKey: null,
        help: false,
        version: false
    };

    let i = 0;
    while (i < args.length) {
        const arg = args[i];

        if (arg === '--help' || arg === '-h') {
            config.help = true;
        } else if (arg === '--version' || arg === '-v') {
            config.version = true;
        } else if (arg === '--expiry' || arg === '-e') {
            i = parseExpiryFlag(args, i, config);
        } else if (arg === '--split' || arg === '-s') {
            config.split = true;
        } else if (arg === '--api-key' || arg === '-k') {
            i = parseApiKeyFlag(args, i, config);
        } else if (!arg.startsWith('-') && !config.secret) {
            config.secret = arg;
        }
        i++;
    }

    return config;
}

/**
 * Read secret from stdin (no mutation — exact bytes preserved).
 * Applies a conservative streaming guard to prevent unbounded memory growth;
 * the definitive byte-length check runs in index.js after encoding.
 * @returns {Promise<string>}
 */
export function readStdin() {
    return new Promise((resolve, reject) => {
        let data = '';

        process.stdin.setEncoding('utf8');
        process.stdin.on('data', (chunk) => {
            data += chunk;
            // Conservative streaming guard: each UTF-16 code unit produces at least
            // 1 UTF-8 byte, so code-unit count > SECRET_MAX_BYTES guarantees byte
            // overflow. The definitive byte check runs in index.js after encoding.
            if (data.length > SECRET_MAX_BYTES) {
                process.stdin.destroy();
                reject(new Error(`Secret too large (max ${SECRET_MAX_BYTES.toLocaleString()} bytes)`));
            }
        });

        process.stdin.on('end', () => {
            resolve(data);
        });

        process.stdin.on('error', reject);
    });
}

/**
 * Print help message
 */
export function printHelp() {
    console.log(`
zephr - Secure one-time secret sharing from the command line

USAGE:
  zephr <secret> [options]
  echo "secret" | zephr [options]

OPTIONS:
  -e, --expiry <hours>   Expiration time: 1, 24, 168, or 720 (default: 1)
                           Without an API key: capped at 1h
                           Free account:       up to 168h (7 days)
                           Dev/Pro account:    up to 720h (30 days)
  -s, --split            Split URL and key for separate transmission
  -k, --api-key <key>    Authenticate with a Zephr API key (overrides ZEPHR_API_KEY)
  -v, --version          Show version number
  -h, --help             Show this help message

AUTHENTICATION:
  API keys unlock longer expiry, higher rate limits, and usage tracking.
  Free account: up to 168h expiry, 50 secrets/month.
  Dev account:  up to 720h expiry, 2,000 secrets/month.
  Pro account:  up to 720h expiry, 50,000 secrets/month.
  Create a key at https://zephr.io/account, then pass it via:
    --api-key zeph_...          flag
    ZEPHR_API_KEY=zeph_... zephr  environment variable

EXAMPLES:
  zephr "my secret password"
  zephr "api-key-12345" --expiry 1
  zephr "sensitive data" --split
  echo "password" | zephr
  cat secret.txt | zephr --expiry 168
  ZEPHR_API_KEY=zeph_... zephr "secret" --expiry 1

OUTPUT:
  Standard mode: Single shareable link
  Split mode:    Separate URL and key for different channels

MORE INFO:
  https://zephr.io
`);
}

/**
 * Print version
 */
export function printVersion() {
    console.log(`zephr ${version}`);
}

/**
 * Print success output
 * @param {{mode: string, url?: string, key?: string, fullLink?: string}} linkData
 * @param {number} expiryHours
 */
export function printSuccess(linkData, expiryHours) {
    console.log('\n[OK] Secret encrypted on your device');
    console.log('[OK] Uploaded to Zephr');

    if (linkData.mode === 'split') {
        console.log('\nSplit mode - share these separately:\n');
        console.log(`URL: ${linkData.url}`);
        console.log(`Key: ${linkData.key}`);
    } else {
        console.log(`\nLink: ${linkData.fullLink}`);
    }

    const EXPIRY_LABELS = { 1: '1 hour', 24: '24 hours', 168: '7 days', 720: '30 days' };
    const expiryText = EXPIRY_LABELS[expiryHours];
    if (!expiryText) throw new Error(`Unexpected expiry value: ${expiryHours}`);
    console.log(`\nExpires in ${expiryText}. One-time access only.\n`);
}

/**
 * Print error message
 * @param {Error} error
 */
export function printError(error) {
    console.error(`\nError: ${error.message}\n`);
}
