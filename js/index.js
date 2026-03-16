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
import { parseArgs, readStdin, printHelp, printVersion, printSuccess, printError } from './cli.js';
import { SECRET_MAX_BYTES } from './limits.js';

/**
 * Main execution flow
 */
async function main() {
    let secretBytes = null;
    let keyBytes = null;
    let exitCode = 0;

    try {
        // Parse arguments
        const args = process.argv.slice(2);
        const config = parseArgs(args);

        // Show help if requested
        if (config.help) {
            printHelp();
            process.exit(0);
        }

        // Show version if requested
        if (config.version) {
            printVersion();
            process.exit(0);
        }

        // Resolve API key early: --api-key flag takes precedence over ZEPHR_API_KEY env var.
        // Done before stdin/crypto so the expiry guard fires before any expensive work.
        const apiKey = config.apiKey ?? process.env.ZEPHR_API_KEY ?? null;

        // Client-side enforcement: anonymous use is capped at 1h.
        // The server enforces this too; this guard gives a clear error before any network call.
        if (apiKey === null && config.expiry > 1) {
            throw new Error(
                'Anonymous use is limited to 1h expiry.\n' +
                'To unlock longer expiry, pass an API key (free: up to 7 days, Dev/Pro: up to 30 days):\n' +
                `  zephr "secret" --expiry ${config.expiry} --api-key zeph_...\n` +
                `  ZEPHR_API_KEY=zeph_... zephr "secret" --expiry ${config.expiry}\n` +
                'Create a free account at https://zephr.io/account'
            );
        }

        // Get secret from args or stdin — validated but never trimmed or mutated.
        let secretText;
        if (config.secret) {
            secretText = config.secret;
        } else {
            if (process.stdin.isTTY) {
                process.stderr.write('Error: provide a secret as an argument or pipe via stdin.\n');
                process.stderr.write('Run "zephr --help" for usage.\n');
                process.exit(1);
            }
            secretText = await readStdin();
        }

        if (!secretText || secretText.trim().length === 0) {
            throw new Error('Secret must not be empty or consist only of whitespace.');
        }

        // Encoding boundary: string → UTF-8 bytes
        secretBytes = new TextEncoder().encode(secretText);

        // Byte-accurate size check — code-unit counting would pass CJK or other
        // multi-byte scripts that exceed the server ceiling (e.g., 1,521 × 3-byte
        // CJK chars = 2,048 code units but 4,563 UTF-8 bytes > 2,048-byte limit).
        if (secretBytes.byteLength > SECRET_MAX_BYTES) {
            throw new Error(`Secret too large (max ${SECRET_MAX_BYTES.toLocaleString()} bytes; input encodes to ${secretBytes.byteLength.toLocaleString()} bytes)`);
        }

        // Generate encryption key
        const key = await generateKey();
        keyBytes = new Uint8Array(await exportKey(key));
        const keyString = createKeyString(keyBytes);

        // Encrypt secret
        const encryptedBlob = await createEncryptedBlob(secretBytes, key);

        // Upload to Zephr
        const result = await uploadSecret(
            encryptedBlob,
            config.expiry,
            config.split,
            apiKey
        );

        // Generate shareable link
        const linkData = generateLink(result.id, keyString, config.split);

        // Print success
        printSuccess(linkData, config.expiry);

    } catch (error) {
        printError(error);
        exitCode = 1;
    } finally {
        // 3-pass memory overwrite matching browser MemoryUtils.overwriteBuffer
        // Pattern: 0x00, 0xFF, 0x00 — best-effort in JS
        if (secretBytes) {
            secretBytes.fill(0);
            secretBytes.fill(0xFF);
            secretBytes.fill(0);
        }
        if (keyBytes) {
            keyBytes.fill(0);
            keyBytes.fill(0xFF);
            keyBytes.fill(0);
        }
    }

    process.exit(exitCode);
}

try {
    await main();
} catch (err) {
    console.error(`\nUnexpected error: ${err.message}\n`);
    process.exit(1);
}
