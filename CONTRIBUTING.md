# Contributing

## Development setup

- Use Node.js 20.19 or newer for development tooling; the package runtime supports Node.js 18 and newer.
- Run `npm ci` to install the locked dependencies.
- Run `npm run check` before opening a pull request. It runs lint, tests, builds the documentation site and embedded playground, and checks the npm package contents.

## Dependency overrides

`package.json` pins `vite` to a patched 6.x release. VitePress pulls in `@vitejs/plugin-vue`, which declares `vite: ^5 || ^6`; the override keeps that transitive dependency on a version without GHSA-8g5g-mxqh-grgj. Do not raise it to Vite 7 or newer until VitePress supports it.

## Changes

- Add or update tests for behavior changes and bug fixes.
- The normative specification has two localized source files: `docs/zh-CN/specification.md` and `docs/en/specification.md`. Keep both versions consistent with each other and with the implementation. Protocol changes must explicitly identify compatibility and security implications.
- Do not commit generated `dist/` output, private keys, or license files containing real customer data.
- Keep pull requests focused and describe user-visible changes and validation performed.

## Releases

Add a Changeset for each user-facing change. When changesets are merged to `main`, the release workflow opens or updates a version pull request. Merging that pull request creates a GitHub Release and publishes the package to npm through trusted publishing.

Before the first release, configure the package's npm trusted publisher to use this repository and `.github/workflows/publish.yml`. GitHub Actions must also be allowed to create pull requests in the repository settings.
