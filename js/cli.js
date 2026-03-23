/**
 * CLI interface - handles user input and output
 * Single responsibility: User interaction
 */

import { createRequire } from 'node:module';
import { SECRET_MAX_BYTES, VALID_EXPIRY } from './limits.js';

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
        throw new Error('--expiry requires a value in minutes (e.g. 5, 15, 30, 60, 1440, 10080, 43200)');
    }
    const value = Number.parseInt(args[i + 1], 10);
    if (!VALID_EXPIRY.has(value)) {
        throw new Error(`Expiry must be one of: ${[...VALID_EXPIRY].join(', ')} minutes`);
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
 * Parse command-line arguments.
 *
 * Supports two modes:
 *   zephr <secret> [options]           — create (default)
 *   zephr retrieve <link> [options]    — retrieve
 *
 * @param {string[]} args - Process arguments (process.argv.slice(2))
 * @returns {object} Parsed config with `mode` field ('create' | 'retrieve')
 */
export function parseArgs(args) {
    // Detect retrieve subcommand before entering the flag loop.
    if (args.length > 0 && args[0] === 'retrieve') {
        return parseRetrieveArgs(args.slice(1));
    }

    return parseCreateArgs(args);
}

/**
 * Parse a flag that requires a value (e.g. --hint <label>).
 * @param {string[]} args
 * @param {number} i  Current index (pointing at the flag).
 * @param {string} flagName  Flag name for error messages.
 * @returns {{ value: string, nextIndex: number }}
 */
function parseValueFlag(args, i, flagName) {
    if (i + 1 >= args.length) throw new Error(`${flagName} requires a value`);
    return { value: args[i + 1], nextIndex: i + 1 };
}

/**
 * Parse arguments for the create subcommand (default mode).
 * @param {string[]} args
 * @returns {object}
 */
function parseCreateArgs(args) {
    const config = {
        mode: 'create',
        secret: null,
        expiry: 60,
        split: false,
        apiKey: null,
        hint: null,
        callbackUrl: null,
        callbackSecret: null,
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
        } else if (arg === '--hint' || arg === '-H') {
            ({ value: config.hint, nextIndex: i } = parseValueFlag(args, i, '--hint'));
        } else if (arg === '--callback-url') {
            ({ value: config.callbackUrl, nextIndex: i } = parseValueFlag(args, i, '--callback-url'));
        } else if (arg === '--callback-secret') {
            ({ value: config.callbackSecret, nextIndex: i } = parseValueFlag(args, i, '--callback-secret'));
        } else if (!arg.startsWith('-') && !config.secret) {
            config.secret = arg;
        }
        i++;
    }

    return config;
}

/**
 * Parse arguments for the retrieve subcommand.
 * @param {string[]} args - Arguments after 'retrieve'
 * @returns {object}
 */
function parseRetrieveArgs(args) {
    const config = {
        mode: 'retrieve',
        link: null,
        retrieveUrl: null,
        retrieveKey: null,
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
        } else if (arg === '--url') {
            if (i + 1 >= args.length) throw new Error('--url requires a value');
            config.retrieveUrl = args[++i];
        } else if (arg === '--key') {
            if (i + 1 >= args.length) throw new Error('--key requires a value');
            config.retrieveKey = args[++i];
        } else if (arg === '--api-key' || arg === '-k') {
            i = parseApiKeyFlag(args, i, config);
        } else if (!arg.startsWith('-') && !config.link) {
            config.link = arg;
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
  zephr <secret> [options]           Create a one-time secret
  echo "secret" | zephr [options]    Create from stdin
  zephr retrieve <link> [options]    Retrieve and decrypt a secret

OPTIONS (create):
  -e, --expiry <minutes> Expiration in minutes (default: 60)
                           5, 15, 30        — Dev/Pro only
                           60 (1h)          — all tiers
                           1440 (24h)       — Free and above
                           10080 (7d)       — Free and above
                           43200 (30d)      — Free and above
  -H, --hint <label>     Plaintext label (e.g. "STRIPE_KEY_PROD"), max 128 chars
  -s, --split            Split URL and key for separate transmission
  -k, --api-key <key>    Authenticate with a Zephr API key (overrides ZEPHR_API_KEY)
  --callback-url <url>   HTTPS webhook URL — receive a signed event on consumption
  --callback-secret <s>  HMAC-SHA256 signing secret for the webhook (required with --callback-url)

OPTIONS (retrieve):
  --url <url>            Secret URL (split mode)
  --key <key>            Encryption key (split mode)
  -k, --api-key <key>    Authenticate with a Zephr API key

GENERAL:
  -v, --version          Show version number
  -h, --help             Show this help message

AUTHENTICATION:
  API keys unlock more expiry options, higher rate limits, and usage tracking.
  Free account: 1h–30d expiry, 50 secrets/month.
  Dev account:  5m–30d expiry, 2,000 secrets/month.
  Pro account:  5m–30d expiry, 50,000 secrets/month.
  Create a key at https://zephr.io/account, then pass it via:
    --api-key zeph_...          flag
    ZEPHR_API_KEY=zeph_... zephr  environment variable

EXAMPLES:
  zephr "my secret password"
  zephr "api-key-12345" --expiry 60
  zephr "db-cred" --expiry 15 --api-key zeph_... --hint "DB_PROD"
  zephr "sensitive data" --split
  echo "password" | zephr --hint "deploy key"
  zephr retrieve "https://zephr.io/secret/abc123...#v1.key..."
  zephr retrieve --url "https://zephr.io/secret/abc123..." --key "v1.key..."

MORE INFO:
  https://zephr.io
`);
}

/**
 * Print retrieve-specific help
 */
export function printRetrieveHelp() {
    console.log(`
zephr retrieve - Retrieve and decrypt a one-time secret

USAGE:
  zephr retrieve <link>                            Standard mode
  zephr retrieve --url <url> --key <key>           Split mode
  echo "https://zephr.io/secret/...#v1..." | zephr retrieve

OPTIONS:
  --url <url>            Secret URL (split mode, without key fragment)
  --key <key>            Encryption key (split mode, e.g. v1.abc...)
  -k, --api-key <key>    Authenticate with a Zephr API key
  -h, --help             Show this help message

The decrypted secret is written to stdout. Errors go to stderr.

EXAMPLES:
  zephr retrieve "https://zephr.io/secret/Ht7kR2mNqP3w#v1.abc..."
  zephr retrieve --url "https://zephr.io/secret/Ht7kR2mNqP3w" --key "v1.abc..."
  SECRET_LINK="https://zephr.io/secret/...#v1..." && zephr retrieve "$SECRET_LINK"
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
 * @param {number} expiry - Expiry in minutes
 */
export function printSuccess(linkData, expiry) {
    console.log('\n[OK] Secret encrypted on your device');
    console.log('[OK] Uploaded to Zephr');

    if (linkData.mode === 'split') {
        console.log('\nSplit mode - share these separately:\n');
        console.log(`URL: ${linkData.url}`);
        console.log(`Key: ${linkData.key}`);
    } else {
        console.log(`\nLink: ${linkData.fullLink}`);
    }

    const EXPIRY_LABELS = {
        5: '5 minutes', 15: '15 minutes', 30: '30 minutes',
        60: '1 hour', 1440: '24 hours', 10080: '7 days', 43200: '30 days'
    };
    const expiryText = EXPIRY_LABELS[expiry];
    if (!expiryText) throw new Error(`Unexpected expiry value: ${expiry}`);
    console.log(`\nExpires in ${expiryText}. One-time access only.\n`);
}

/**
 * Print error message
 * @param {Error} error
 */
export function printError(error) {
    console.error(`\nError: ${error.message}\n`);
}
