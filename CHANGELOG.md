# Changelog

## Unreleased

- **Security**: Fix CSRF enforcement by correcting middleware ordering so authenticated unsafe requests require `x-csrf-token`.
- **Developer Experience**: Exclude local dev state (`.local-config/`) from Docker build context to prevent build failures.

