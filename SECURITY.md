# Security notes

- Production sessions use `HttpOnly`, `Secure`, `SameSite=Lax` cookies.
- Passwords are stored as PBKDF2-HMAC-SHA256 hashes with unique random salts.
- Database credentials must be supplied only through the host's private environment variables.
- The server does not accept client-side database seeding.
- State updates are constrained to records associated with the authenticated account; this legacy collection bridge is transitional and should be replaced by explicit resource endpoints before a broad public launch.
- Configure `ALLOWED_ORIGINS` to the exact deployed origin(s).
- Do not store sensitive student information unless needed, and publish a privacy notice before opening registrations.
