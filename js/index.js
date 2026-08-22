#!/usr/bin/env node

/**
 * Zephr CLI - Command-line tool for secure one-time secret sharing
 *
 * Architecture:
 * - sdk.js: createSecret/retrieveSecret (validation, crypto, HTTP)
 * - cli.js: User interface (args, stdin, output)
 * - index.js: Orchestrator (this file)
 *
 * The CLI is a thin shell over the SDK: both directions go through the
 * same validation, encryption, and transport code that npm consumers use.
 */

import { parseArgs, readStdin, printHelp, printRetrieveHelp, printVersion, printSuccess, printError } from './cli.js';
import { createSecret, retrieveSecret } from './sdk.js';

// ---------------------------------------------------------------------------
// Helpers — extracted to keep main() linear and under Sonar's complexity cap.
// ---------------------------------------------------------------------------

/** Resolve API key: flag > env var > null. Treats empty strings as absent. */
function resolveApiKey(config) {
    const key = config.apiKey ?? process.env.ZEPHR_API_KEY ?? null;
    return (typeof key === 'string' && key.trim().length === 0) ? null : key;
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

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
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

        // Pre-check with CLI-appropriate phrasing; the SDK enforces the same
        // rule but its message names SDK options, not flags.
        if (apiKey === null && config.callbackUrl) {
            throw new Error(
                'Webhook callbacks require authentication.\n' +
                'Pass an API key to use --callback-url:\n' +
                '  zephr "secret" --callback-url https://... --callback-secret ... --api-key zeph_...\n' +
                'Create a free account at https://zephr.io/account'
            );
        }

        const secretText = await resolveSecretText(config);

        // Validation (emptiness, byte length, hint/callback shape), encryption,
        // upload, and buffer zeroing all live in the SDK — the CLI adds nothing.
        const result = await createSecret(secretText, {
            expiry:         config.expiry,
            split:          config.split,
            apiKey,
            hint:           config.hint ?? undefined,
            callbackUrl:    config.callbackUrl ?? undefined,
            callbackSecret: config.callbackSecret ?? undefined,
        });

        printSuccess(result, config.expiry);

    } catch (error) {
        printError(error);
        exitCode = 1;
    }

    process.exit(exitCode);
}

try {
    await main();
} catch (err) {
    console.error(`\nUnexpected error: ${err.message}\n`);
    process.exit(1);
}
