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
        const valueField = CREATE_VALUE_FLAGS[arg];

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
        } else if (valueField) {
            ({ value: config[valueField], nextIndex: i } = parseValueFlag(args, i, arg));
        } else {
            acceptPositional(config, 'secret', arg, 'zephr --help');
        }
        i++;
    }

    return config;
}

/** Value-taking create flags mapped to their config field. */
const CREATE_VALUE_FLAGS = Object.freeze({
    '--hint':            'hint',
    '-H':                'hint',
    '--callback-url':    'callbackUrl',
    '--callback-secret': 'callbackSecret',
});

/**
 * Accept a positional argument into config[field], rejecting unknown flags
 * and surplus positionals. A typo'd flag silently falling through is not
 * harmless here: a mistyped --expiry means the secret ships with the
 * default window.
 *
 * @param {object} config
 * @param {string} field    Config key the positional fills (once).
 * @param {string} arg      The token being examined.
 * @param {string} helpCmd  Help command for the error message.
 */
function acceptPositional(config, field, arg, helpCmd) {
    if (arg.startsWith('-')) {
        throw new Error(`Unknown option: "${arg}". Run "${helpCmd}" for usage.`);
    }
    if (config[field]) {
        throw new Error(`Unexpected argument: "${arg}". Run "${helpCmd}" for usage.`);
    }
    config[field] = arg;
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
            ({ value: config.retrieveUrl, nextIndex: i } = parseValueFlag(args, i, '--url'));
        } else if (arg === '--key') {
            ({ value: config.retrieveKey, nextIndex: i } = parseValueFlag(args, i, '--key'));
        } else if (arg === '--api-key' || arg === '-k') {
            i = parseApiKeyFlag(args, i, config);
        } else {
            acceptPositional(config, 'link', arg, 'zephr retrieve --help');
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
                           5, 15, 30, 60    — anonymous or authenticated
                           1440 (24h)       — requires an API key
                           10080 (7d)       — requires an API key
                           43200 (30d)      — requires an API key
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
  An API key unlocks every expiry value, a higher quota, larger payloads,
  and webhook callbacks. Accounts are free.
  Anonymous:    up to 1h expiry (5m/15m/30m/1h), 3 secrets/day.
  Free account: 5m–30d expiry, 500 secrets/month.
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

    console.log(`\nExpires in ${formatExpiryMinutes(expiry)}. One-time access only.\n`);
}

/**
 * Human label for an expiry in minutes: "5 minutes", "1 hour", "24 hours",
 * "7 days". Total — never throws: once the upload has succeeded, nothing on
 * the output path may fail, or the link is lost while the secret exists.
 * Copy of server/utils/duration.js formatExpiryMinutes (the packaged CLI
 * cannot import server/); tests/tiers.test.js pins the copies' agreement.
 * @param {number} minutes
 * @returns {string}
 */
export function formatExpiryMinutes(minutes) {
    if (minutes % 1440 === 0 && minutes > 1440) {
        return `${minutes / 1440} days`;
    }
    if (minutes % 60 === 0 && minutes >= 60) {
        const hours = minutes / 60;
        return `${hours} hour${hours === 1 ? '' : 's'}`;
    }
    return `${minutes} minute${minutes === 1 ? '' : 's'}`;
}

/**
 * Print error message
 * @param {Error} error
 */
export function printError(error) {
    console.error(`\nError: ${error.message}\n`);
}
