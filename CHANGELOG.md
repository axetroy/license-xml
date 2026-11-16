# Changelog

Notable changes to License XML are documented here.

## 0.1.2

### Patch Changes

- c058a04: Enforce that `perpetual` licenses omit `expiresAt` and that `trial`/`subscription` licenses require it, matching the specification. Previously a signed `perpetual` license carrying an `expiresAt` was accepted by the library while the playground rejected it.
  
  Also harden the API and tooling:
  
  - `verifyLicense` now tolerates a missing or `null` options object instead of throwing, and ignores inherited properties on plain-object key registries.
  - The payload parser and serializer are shared with the browser playground, removing a second, drift-prone implementation.
  - The CLI is now importable and covered by tests; coverage spans the library, the shared protocol module, and the CLI.
  - Added TypeScript type declarations, a `.nvmrc`, and `coverage/` to `.gitignore`; CI uploads the coverage report.

## 0.1.1

### Patch Changes

- 933cf18: Add the MIT license and automate versioning and npm releases with Changesets.

## 0.1.0

- Initial License XML v1.0 specification and JavaScript implementation.
- Ed25519 signing and offline verification library and CLI.
- Node.js tests, linting, CI, trusted npm publishing, and GitHub Pages playground.
