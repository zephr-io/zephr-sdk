#!/usr/bin/env node

// Only warn during global installs (`npm install -g zephr`).
// Local installs and npx skip this entirely.

const isGlobal = process.env.npm_config_global === 'true'
  || process.env.npm_config_global === ''  // npm 9+ sets empty string for --global
  || (process.env.npm_lifecycle_event === 'postinstall' && !process.env.INIT_CWD?.includes('node_modules'));

if (!isGlobal) process.exit(0);

import { execSync } from 'node:child_process';
import { join } from 'node:path';

try {
    // npm 9+ removed `npm bin -g`. Derive bin dir from the global prefix instead.
    const prefix = execSync('npm config get prefix', { encoding: 'utf8' }).trim();
    const binDir = process.platform === 'win32' ? prefix : join(prefix, 'bin');
    const pathDirs = (process.env.PATH || '').split(process.platform === 'win32' ? ';' : ':');

    if (!pathDirs.includes(binDir)) {
        const shell = process.env.SHELL || '';
        const RC_FILES = [
            ['zsh', '~/.zshrc'],
            ['bash', '~/.bashrc'],
        ];
        const rcFile = RC_FILES.find(([sh]) => shell.includes(sh))?.[1] ?? '~/.profile';

        console.log('');
        console.log('\x1b[33m⚠  zephr was installed, but the npm bin directory is not in your PATH.\x1b[0m');
        console.log('');
        console.log(`   Add this to ${rcFile}:`);
        console.log(`     export PATH="${binDir}:$PATH"`);
        console.log('');
        console.log('   Or skip global install entirely — npx zephr always works:');
        console.log('     echo "my secret" | npx zephr');
        console.log('');
    }
} catch {
    // Silently ignore — never block installation.
}
