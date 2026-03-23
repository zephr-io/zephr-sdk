#!/usr/bin/env node

/**
 * Zephr CLI - Command-line tool for secure one-time secret sharing
 *
 * Architecture:
 * - crypto.js: Encryption logic (AES-GCM-256)
 * - api.js: HTTP communication with Zephr server
 * - link.js: URL generation
 * - cli.js: User interface (args, stdin, output)
 * - index.js: Orchestrator (this file)
 *
 * Design principles:
 * - Single responsibility per module
 * - No dependencies (uses Node.js built-ins only)
 * - Compatible with browser crypto implementation
 * - Testable (pure functions, dependency injection)
 */

import { generateKey, exportKey, createEncryptedBlob, createKeyString } from './crypto.js';
import { uploadSecret } from './api.js';
import { generateLink } from './link.js';
import { parseArgs, readStdin, printHelp, printRetrieveHelp, printVersion, printSuccess, printError } from './cli.js';
import { retrieveSecret } from './sdk.js';
import { SECRET_MAX_BYTES } from './limits.js';

// ---------------------------------------------------------------------------
// Helpers — extracted to keep main() linear and under Sonar's complexity cap.
// ---------------------------------------------------------------------------

/** Resolve API key: flag > env var > null. */
function resolveApiKey(config) {
    return config.apiKey ?? process.env.ZEPHR_API_KEY ?? null;
}

/** Handle --help and --version flags. Exits the process if either is set. */
function handleInfoFlags(config) {
    if (config.help) {
        (config.mode === 'retrieve' ? printRetrieveHelp : printHelp)();
        process.exit(0);
    }
    if (config.version) {
        printVersion();
        process.exit(0);
    }
}

/** Resolve the link input for retrieve mode from config or stdin. */
async function resolveRetrieveLink(config) {
    if (config.link) return config.link;

    if (config.retrieveUrl || config.retrieveKey) {
        if (!config.retrieveUrl) throw new Error('--url is required when using --key (split mode).');
        if (!config.retrieveKey) throw new Error('--key is required when using --url (split mode).');
        return { url: config.retrieveUrl, key: config.retrieveKey };
    }

    if (!process.stdin.isTTY) return (await readStdin()).trim();

    throw new Error(
        'Provide a link to retrieve:\n' +
        '  zephr retrieve "https://zephr.io/secret/...#v1..."\n' +
        '  zephr retrieve --url "..." --key "v1..."\n' +
        'Run "zephr retrieve --help" for usage.'
    );
}

/** Execute the retrieve flow: fetch, decrypt, print. */
async function runRetrieve(config, apiKey) {
    const link = await resolveRetrieveLink(config);
    const result = await retrieveSecret(link, { apiKey });
    if (result.hint) process.stderr.write(`Hint: ${result.hint}\n`);
    process.stdout.write(result.plaintext);
    process.exit(0);
}

/** Read the secret text from config arg or stdin. */
async function resolveSecretText(config) {
    if (config.secret) return config.secret;

    if (process.stdin.isTTY) {
        process.stderr.write('Error: provide a secret as an argument or pipe via stdin.\n');
        process.stderr.write('Run "zephr --help" for usage.\n');
        process.exit(1);
    }

    return readStdin();
}

/** 3-pass memory overwrite matching browser MemoryUtils.overwriteBuffer. */
function zeroBuffer(buf) {
    if (!buf) return;
    buf.fill(0x00);
    buf.fill(0xFF);
    buf.fill(0x00);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
    let secretBytes = null;
    let keyBytes = null;
    let exitCode = 0;

    try {
        const config = parseArgs(process.argv.slice(2));

        handleInfoFlags(config);

        const apiKey = resolveApiKey(config);

        // Retrieve mode — separate flow, exits on success
        if (config.mode === 'retrieve') {
            await runRetrieve(config, apiKey);
            return; // unreachable (runRetrieve exits), but explicit for clarity
        }

        // Client-side enforcement: anonymous use is capped at 60 minutes (1h).
        if (apiKey === null && config.expiry !== 60) {
            throw new Error(
                'Anonymous use is limited to 60-minute (1h) expiry.\n' +
                'To unlock more expiry options, pass an API key (free: up to 30d, Dev/Pro: adds sub-hour):\n' +
                `  zephr "secret" --expiry ${config.expiry} --api-key zeph_...\n` +
                `  ZEPHR_API_KEY=zeph_... zephr "secret" --expiry ${config.expiry}\n` +
                'Create a free account at https://zephr.io/account'
            );
        }

        // Client-side enforcement: webhook callbacks require authentication.
        if (apiKey === null && config.callbackUrl) {
            throw new Error(
                'Webhook callbacks require authentication.\n' +
                'Pass an API key to use --callback-url:\n' +
                '  zephr "secret" --callback-url https://... --callback-secret ... --api-key zeph_...\n' +
                'Create a free account at https://zephr.io/account'
            );
        }

        const secretText = await resolveSecretText(config);

        if (!secretText || secretText.trim().length === 0) {
            throw new Error('Secret must not be empty or consist only of whitespace.');
        }

        secretBytes = new TextEncoder().encode(secretText);

        if (secretBytes.byteLength > SECRET_MAX_BYTES) {
            throw new Error(`Secret too large (max ${SECRET_MAX_BYTES.toLocaleString()} bytes; input encodes to ${secretBytes.byteLength.toLocaleString()} bytes)`);
        }

        const key = await generateKey();
        keyBytes = new Uint8Array(await exportKey(key));
        const keyString = createKeyString(keyBytes);
        const encryptedBlob = await createEncryptedBlob(secretBytes, key);

        const result = await uploadSecret(
            encryptedBlob,
            config.expiry,
            config.split,
            config.hint ?? undefined,
            apiKey,
            {
                callbackUrl: config.callbackUrl ?? undefined,
                callbackSecret: config.callbackSecret ?? undefined,
            },
        );

        const linkData = generateLink(result.id, keyString, config.split);
        printSuccess(linkData, config.expiry);

    } catch (error) {
        printError(error);
        exitCode = 1;
    } finally {
        zeroBuffer(secretBytes);
        zeroBuffer(keyBytes);
    }

    process.exit(exitCode);
}

try {
    await main();
} catch (err) {
    console.error(`\nUnexpected error: ${err.message}\n`);
    process.exit(1);
}
