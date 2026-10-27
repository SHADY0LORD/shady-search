# Shady Search private API (staging scaffold)

This folder adds a server-side API scaffold. It is **not production-ready until configured, migrated, and tested**. The current static app is not connected to this API yet.

## Important safety rules

- Do not upload customer records, CSV files, database chunks, passwords, or session secrets to GitHub.
- Do not delete or overwrite the original database. Make an independent backup first.
- The existing database chunks total about 675.5 MiB. Measure a rebuilt staging copy before choosing D1; D1 Free's per-database size limit may be too small.
- A private repository or login screen does not protect data that the browser downloads. Do not deploy the current static app as a secure production app while it still fetches `data/customers.db.partNNN`.
- `schema.sql` reflects the fields currently used by the UI, not a verified full source schema. Inventory the actual source columns and row count before importing. Preserve every source field in a backup/staging copy.

## What is implemented here

- Worker routes: `/api/health`, `/api/auth/login`, `/api/auth/logout`, `/api/auth/me`, and authenticated `/api/search`.
- Passwords stored as PBKDF2-SHA256 hashes, not plain text.
- Signed expiring session cookie with HttpOnly, Secure, SameSite=Strict; server-side session record and active-user check.
- Separate `admin` / `user` roles in schema; admin endpoints are denied for non-admins. User-management routes still need implementation.
- Prepared SQL statements and a 100-result cap; only UI-needed fields are returned.
- No customer-data import or production cutover has been performed.

## Prerequisites

Install Node.js LTS and Wrangler locally. Do not put real passwords into terminal history.

```bash
npm install --save-dev wrangler
npx wrangler login
```

Create a D1 database and update `database_id` in `wrangler.toml`. Apply the schema to a **staging** database first:

```bash
npx wrangler d1 create shady-search-private
npx wrangler d1 execute shady-search-private --remote --file=backend/schema.sql
npx wrangler secret put SESSION_SECRET
```

When asked for `SESSION_SECRET`, provide a random secret of at least 32 characters. Keep it out of GitHub.

## Create the first admin

1. Create a strong password of at least 12 characters.
2. Generate a hash locally without saving the password in shell history:
   - PowerShell: `Read-Host -AsSecureString` alone is not enough to pipe securely to Node. Use a local secure prompt/script and pass the password to `node backend/hash-password.mjs` through stdin without echoing it.
   - The utility reads the password from stdin and prints only the hash.
3. Insert the account into the staging D1 database using a prepared/escaped SQL statement. Do not paste a plain password into SQL, a commit, or a screenshot. Example SQL shape:
   `INSERT INTO users(username,password_hash,role,is_active) VALUES('your-admin-username','<GENERATED_HASH>','admin',1);`
4. Never reuse the old static password `1234`.

## First task: inventory your original database safely

Make a separate backup first. Then run the read-only inventory script on your own computer; it prints schema/counts and a checksum, not customer records.

```bash
python backend/inspect_source_db.py "PATH/TO/customers.db"
```

On Windows, replace the example with the actual path, for example `python backend/inspect_source_db.py "D:\\ShadySearch\\customers.db"`. Keep the original database unchanged. Send me the JSON output from this command (it should contain no customer names or phone numbers) so we can choose the right storage and migration approach.

## Data migration — required before connecting the UI

1. Keep a read-only copy of the original database and record its SHA-256 checksum.
2. Use a local script to report table names, all columns/types, indexes, exact row count, distinct area count, null counts, and DB file size. Do not publish sample customer names/phones.
3. Determine whether the full source can fit the target database. The current chunks are ~675.5 MiB before any rebuild, so do not assume D1 Free will fit.
4. Import to staging in batches, preserving all original columns and a stable source ID.
5. Compare source and target row counts, schema, null counts, distinct areas, and a deterministic sample of records. Keep a backup until all checks pass.
6. Benchmark name, phone, address, multi-term, and area searches. Current substring `LIKE '%term%'` may scan many rows; use a measured FTS/trigram/index design if needed.
7. Test login failures, expired sessions, disabled users, cross-origin requests, and unauthenticated search requests.
8. Only after passing checks, update the front-end to call this API and remove all client-side DB chunk loading. Then deploy and verify no database file is publicly served.

## Current limitation

This is a safe starting scaffold, not a completed deployment. The current `app.js` still uses hard-coded credentials and downloads the complete database. Do not merge this into production or call the app secure until the front end is migrated, data import is verified, and the security checks pass.
