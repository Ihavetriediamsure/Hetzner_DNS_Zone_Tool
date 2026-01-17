# Changelog

## Unreleased

- **Security**: Fix CSRF enforcement by correcting middleware ordering so authenticated unsafe requests require `x-csrf-token`.
- **Developer Experience**: Exclude local dev state (`.local-config/`) from Docker build context to prevent build failures.
- **Peer-Sync**: When `ssl_enabled=true`, automatically upgrade misconfigured `http://` peer URLs to `https://` to prevent sync breakage.
- **Developer Experience**: Exclude local peer test volumes (`.peer1-config/`, `.peer2-config/`) from Docker build context.

