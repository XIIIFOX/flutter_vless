# Documentation Index

This directory is the canonical local documentation set for `flutter_vless`.

The package page on pub.dev is driven by the root `README.md`. These guides keep the longer setup, configuration, and troubleshooting material in one place without turning the pub.dev page into a wall of text.

## Read This First

1. [Getting Started](getting-started.md)
2. [Platform Guides](platform/README.md)
3. [API Contract](api.md)
4. [Runtime diagnostics](runtime-diagnostics.md)
5. [Examples](examples.md)
6. [Configuration Guide](configuration.md)
7. [Compatibility](compatibility.md)
8. [Security And Runtime Boundaries](security.md)
9. [Architecture Notes](architecture.md)
10. [Real-Device VPN Matrix](device_matrix.md)
11. [Troubleshooting](troubleshooting.md)

## Audience Split

- New users should start with `getting-started.md`, `examples.md`, and their platform guide.
- Integrators should read `api.md`, `configuration.md`, and `compatibility.md`.
- Maintainers should read `architecture.md`, `security.md`, and the macOS packet tunnel note before changing native runtime behavior.
- Release validation should use `device_matrix.md` when VPN/tunnel behavior changes.
- Debugging issues should usually begin with `troubleshooting.md`.

## Notes

- Keep this directory as the source of truth for human-written docs.
- Use `README.md` for the pub.dev-facing summary and quick start.
- Treat older root-level setup files as legacy during the transition to this docs layout.
