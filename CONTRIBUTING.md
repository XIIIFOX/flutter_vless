# CONTRIBUTING.md

Thank you for considering contributing to `flutter_vless`! This document explains how to report issues, propose changes, and submit pull requests so your contributions can be reviewed and merged quickly.

## Table of contents
- How to file an issue
- Code style & linters
- Branching & pull request workflow
- Tests and CI
- PR checklist
- Review process and maintainers
- Local development notes
- Security / responsible disclosure

## How to file an issue
When filing an issue, please include:
1. A short, descriptive title.
2. Reproduction steps (exact steps to reproduce the bug).
3. Environment information: OS (iOS/Android), device/emulator, Flutter version, plugin version.
4. Relevant logs or error messages (paste or attach a file).
5. A minimal reproduction example if possible (small project or sandbox).

## Code style & linters
- Run `dart format` on changed files before submitting a PR.
- Run `flutter analyze` and fix any analyzer issues flagged by the project.
- Use null-safety idioms and prefer small, well-tested changes.

Follow the project's lint rules.

## Branching & pull request workflow
1. Fork the repository.
2. Create a feature branch named `feat/short-description` or `fix/short-description` from `main`.
3. Commit changes with clear messages.
4. Open a Pull Request against `main` and reference the related issue (e.g., `Fixes #123`).

If you are adding significant behavior or changing the public API, open an issue first to discuss the design.

## Tests and CI
- Add unit tests for new functionality when possible.
- Run tests locally with `flutter test`.
- Ensure CI passes on your branch before requesting a review.

If the project uses additional integration or platform tests, include instructions on how to run them locally.

## Pull Request checklist
Before requesting a review, ensure:
- [ ] The PR has a descriptive title and summary.
- [ ] Related issue is referenced or created.
- [ ] Code is formatted (`dart format`).
- [ ] Static analysis (`flutter analyze`) shows no new warnings.
- [ ] Tests added/updated and passing (`flutter test`).
- [ ] Documentation updated (README, API docs) for public API changes.
- [ ] Platform-specific notes included if behaviour on iOS/Android changed.

## Review process and maintainers
- PRs are reviewed by the maintainers and contributors listed in the repository.
- Expect an initial review within a few business days (varies by maintainer availability).
- Reviewers may request changes — please address them with follow-up commits.

If you want to be listed as a maintainer, open an issue explaining your contributions and activity.

## Local development notes
- To run the example app: `cd example && flutter run`.
- For iOS extension development (Network Extension / PacketTunnel) use Xcode to open `ios/Runner.xcworkspace` and build the extension target.
- Keep secrets (API keys, certificates) out of the repository; use environment variables or local config files ignored by git.

## Security / responsible disclosure
If you discover a security vulnerability, please report it privately to: **13fox.comp@gmail.com**

Provide:
- A description of the vulnerability and reproduction steps.
- Impact assessment and suggested mitigation (if known).

The maintainer will acknowledge within 3 business days and work on a fix or coordinated disclosure.

## CLA (Contributor License Agreement)
This repository **does not require** a Contributor License Agreement (CLA) by default. Contributors submit code under the project's MIT license by creating a pull request.

If you prefer to require CLAs in the future, we can add a CLA process and templates.

