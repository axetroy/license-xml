---
"license-xml": patch
---

Enforce that `perpetual` licenses omit `expiresAt` and that `trial`/`subscription` licenses require it, matching the specification. Previously a signed `perpetual` license carrying an `expiresAt` was accepted by the library while the playground rejected it.

Also harden the API and tooling:

- `verifyLicense` now tolerates a missing or `null` options object instead of throwing, and ignores inherited properties on plain-object key registries.
- The payload parser and serializer are shared with the browser playground, removing a second, drift-prone implementation.
- The CLI is now importable and covered by tests; coverage spans the library, the shared protocol module, and the CLI.
- Added TypeScript type declarations, a `.nvmrc`, and `coverage/` to `.gitignore`; CI uploads the coverage report.
