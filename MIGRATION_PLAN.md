# Shady Search — Security-First Upgrade Plan

## Current state (verified from the repository)

- The current app is a static HTML/CSS/JavaScript PWA (\`index.html\`, \`app.js\`, \`service-worker.js\`) with SQLite WASM in the browser.
- \`app.js\` contains a hard-coded shared username/password and stores an authentication flag in \`localStorage\`. This is not server-side authentication.
- The browser downloads and assembles the full customer database from \`data/customers.db.partNNN\`, then caches it locally. A user can retrieve the data even if the UI asks them to log in.
- The \`data/\` directory currently contains 34 database chunks totaling **708,177,920 bytes (~675.5 MiB)**. The exact database schema and row count still need to be measured from the original database before migration.
- Existing data must not be overwritten or deleted until a verified backup and a successful import have been confirmed.

## Target architecture

Keep the existing lightweight front end as a transition step; move customer records and all search execution behind an authenticated server API. Do not send database files, bulk exports, or unrestricted result sets to the browser.

Proposed low-cost stack:
- Front end: keep the current HTML/CSS/JS initially; redesign it after the secure API works. A framework migration is optional, not a prerequisite.
- API and server-side authentication: Cloudflare Workers.
- Database candidate: Cloudflare D1, **only if** a rebuilt/normalized database fits its current Free-plan 500 MB per-database limit and the expected usage fits the daily quotas. The current chunked database is ~675.5 MiB, so it does not fit as-is. Benchmark compression/normalization and import size first. If it still exceeds the limit, do not force an unsafe or lossy import; compare a paid D1 tier or another host with adequate storage before proceeding.
- Use server-side password hashing, expiring sessions in Secure/HttpOnly/SameSite cookies, rate limiting, and role checks on every protected endpoint. Never store a shared password or treat a localStorage flag as proof of authentication.
- All SQL must use prepared/bound parameters. Return only the minimum fields required for a search result and enforce a small server-side result limit.

## Implementation phases

### Phase 0 — Contain exposure and preserve the source
1. Create and verify an independent backup of the original database and the source CSV (if available).
2. Record the source database checksum, schema, exact row count, distinct area count, and representative samples without exposing personal data in logs.
3. Identify every public deployment and old database URL. A private GitHub repository alone does not revoke copies or previously deployed static assets.
4. Keep production changes separate from this branch until the secure API and import are verified. Once migration is ready, remove data chunks from public deployment paths and clean Git history if the database was ever committed to a public repository. Rotating/removing a file in a new commit alone does not erase old Git history or downloaded copies.

### Phase 1 — Private backend and separate accounts
1. Add a server API with \`/api/auth/login\`, \`/api/auth/logout\`, \`/api/auth/me\`, and \`/api/search\`.
2. Store users in a server-side users table; support \`admin\` and \`user\` roles, disabled accounts, and per-user credentials.
3. Store session identifiers hashed server-side where practical; use secure cookies and validate sessions server-side.
4. Add login throttling, generic login errors, input validation, security headers, and audit metadata that avoids logging customer search terms or full records by default.
5. Add automated checks proving unauthenticated requests cannot search, disabled accounts cannot search, and normal users cannot access admin actions.

### Phase 2 — Data migration without loss
1. Create a read-only inventory of the existing database: table names, column names/types, row count, file size, and indexes.
2. Rebuild or normalize a staging copy; preserve all source columns and a stable source ID. Do not discard duplicates without an explicit deduplication rule.
3. Import in batches into a staging database.
4. Compare total rows, null counts, distinct area counts, and sampled records between source and target.
5. Benchmark searches for names, phone numbers, addresses, and areas; add indexes or full-text indexes based on actual query patterns.
6. Switch the API to the imported database only after all checks pass; retain a recoverable backup until post-cutover verification is complete.

### Phase 3 — Search and responsive redesign
- Keep Arabic RTL and the existing installable PWA behavior where compatible.
- Add responsive desktop/mobile layouts, light/dark themes, accessible controls, loading/empty/error states, keyboard support, and clear result cards.
- Normalize Arabic/English digits and whitespace in search inputs; support multi-term search without full-table scans.
- Use server-side pagination and a strict result cap; never download the full database to the client.
- Add request cancellation/debouncing and performance measurements.

### Phase 4 — Administration, monitoring, and launch
- Admin-only user creation/disable/reset workflows; do not expose open self-registration unless explicitly required.
- Add basic health checks, error monitoring without customer PII, database backup/export procedures, and a documented restore test.
- Test mobile, desktop, expired sessions, rate limits, common searches, and production deployment before retiring the old static version.

## Acceptance criteria

- No customer database chunks or customer records are served as static assets.
- No hard-coded shared credentials exist in front-end files.
- An unauthenticated or disabled user cannot call the search API successfully.
- Each account has its own credentials; admin actions are role-protected server-side.
- Search responses contain only the fields needed by the UI and are capped/paginated.
- Source and target row counts match, and documented data-integrity checks pass.
- The new version is tested on desktop and mobile before production cutover.

## Important sizing decision

The current database chunks total ~675.5 MiB. Cloudflare D1 Free currently allows 500 MB per database, so the current file cannot be imported there unchanged. First measure the actual database contents and test a safe rebuilt copy. Do not promise a fully free production deployment until storage and expected daily query volume have been validated.
