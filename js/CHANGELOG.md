# Changelog

All notable changes to the `zephr` npm package (JS SDK and CLI).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases before 2.0.0 predate this file; see the `npm-v*` git tags for that history.

## [2.0.0] - 2026-08-16

### Breaking

- `retrieveSecret()` now resolves `purgeAt` as a **number** — a Unix timestamp
  in seconds — instead of a string.

  It was previously documented as an ISO 8601 timestamp but returned the
  numeric wire value coerced with `String()`, so it arrived as `"1771957320"`
  and never parsed as a date. The type now matches what the API actually
  returns.

  ```js
  // before (never worked as documented)
  new Date(result.purgeAt);

  // after
  new Date(result.purgeAt * 1000);
  ```

  `TypeScript` users will see the change in `types.d.ts` as `purgeAt?: number`.

### Added

- Anonymous callers may now use 5, 15 and 30 minute expiries, not only 60.

### Changed

- `SECRET_MAX_BYTES` raised from 2,048 to 14,336 UTF-8 bytes (7×), derived from
  the 20KB encrypted-blob ceiling the free tier allows.
- Account tiers simplified to anonymous and free; the free monthly quota is now
  500 creates. References to Dev and Pro plans are removed from `--help`.

### Changed (CLI)

- The CLI's create path now goes through the SDK's `createSecret()` — the
  same validation, encryption, and transport code npm consumers use. The
  CLI-only crypto and HTTP modules are gone, and callback URLs and hints
  are now validated client-side in the CLI exactly as in the SDK.
- The `User-Agent` on CLI requests is now `zephr-js/<version>` (previously
  `zephr-cli/<version>`), reflecting the shared HTTP client.
- Unknown flags and stray positional arguments are now errors. A typo'd
  flag (`--expirey 30`) used to be silently ignored, shipping the secret
  with the default 60-minute window.

### Removed

- The `postinstall` PATH-check script. It misdetected local installs as
  global, spawned `npm config get prefix` on every install, and install
  scripts are a supply-chain liability in a security-focused package. Use
  `npx zephr` if the global npm bin directory is not on your PATH.

### Fixed

- `retrieveSecret()` now validates the encryption key **before** the one-time
  fetch. Retrieval consumes the record, so a truncated or mangled key
  previously destroyed the secret and then failed to decrypt it — losing it
  permanently. A malformed key now throws `EncryptionError` offline, with the
  secret still retrievable using a corrected link.
- Browser bundling works again. `sdk-api.js` imported `node:module` to read
  the package version, which failed to resolve in browser bundlers (esbuild,
  webpack 5); the version now comes from a JSON import attribute, native in
  Node 22+ and supported by all major bundlers.
- The SDK and CLI no longer reject sub-hour expiries for anonymous callers.
  Both carried a local copy of a server rule (`expiry !== 60`) that went stale
  when the anonymous allowance widened, so requests the server accepts failed
  before ever being sent. Which expiry values a tier may use is now decided
  solely by the server, which returns `403 UPGRADE_REQUIRED` listing the
  permitted values.
- `--help` no longer claims anonymous use is limited to a 1 hour expiry while
  its own `--expiry` section lists 5, 15 and 30 as anonymous-capable.
