# Security Hardening — AI Command Center

## Audit Date: 2026-03-18

---

## Fixes Applied

### H4 — CORS Restriction
**File:** `server.js` (middleware section)
**What:** Replaced `cors()` (allow all origins) with origin whitelist.
**Config:** Set `ALLOWED_ORIGINS` env var (comma-separated). Defaults to `http://localhost:3000`.
**Production:** Add your Railway domain: `ALLOWED_ORIGINS=https://yourdomain.railway.app`

### H5 — Rate Limiting
**File:** `server.js` (middleware section)
**Limits:**
- `/auth/login` — 10 requests / 15 min (brute-force protection)
- `/api/chat/gemini` — 10 requests / 1 min (API cost protection)
- `/api/radar/scan` — 5 requests / 1 min (API cost protection)
- `/api/*` — 200 requests / 1 min (general flood protection)

### M1 — Security Headers (helmet)
**File:** `server.js` (middleware section)
**Headers added:**
- Content-Security-Policy (restricts script/style/connect sources)
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY (clickjacking protection)
- Strict-Transport-Security (HSTS)
- Referrer-Policy
- X-DNS-Prefetch-Control

**Note:** CSP allows `'unsafe-inline'` for scripts/styles since the app is a single-file SPA. To tighten further, refactor inline scripts to external files and use nonces.

### M2 — Static File Isolation
**File:** `server.js` (middleware section)
**What:** Changed `express.static(__dirname)` to `express.static('public/')`.
**Effect:** Only files in `public/` are served. `server.js`, `package.json`, `.env` are no longer accessible via HTTP.
**Structure:** `public/index.html` is a symlink to `../index.html`.

### H1 — Mass Assignment Protection
**File:** `server.js` (all PATCH endpoints)
**What:** All 10 PATCH endpoints now whitelist allowed fields instead of passing `req.body` directly to `.update()`.
**Tables protected:** companies, tasks, logs, tools, events, docs, ideas, contacts, recurring-tasks, scratches

### C3 — Destructive Endpoint Confirmation
**File:** `server.js` (`DELETE /api/reset`)
**What:** Requires `{ "confirm": "DELETE_ALL_DATA" }` in request body.
**Frontend:** Updated to send confirmation body. Still requires user to type "DELETE" in a prompt dialog.

### L4 — Startup Banner
**What:** Removed Supabase URL and bucket name from console output.

---

## Remaining Items (Future Work)

### HIGH Priority

| ID | Issue | Description | Effort |
|---|---|---|---|
| H2 | API keys in browser | OpenAI/Claude/Grok keys sent from frontend. Proxy through server. | 3-4 hrs |
| H3 | Stored XSS | ~15 innerHTML locations render DB content unsanitized. Add DOMPurify or escape function. | 3-4 hrs |

### MEDIUM Priority

| ID | Issue | Description | Effort |
|---|---|---|---|
| C2 | Service key for all ops | Switch user-facing queries to anon key with per-request JWT. | 2-4 hrs |
| M3 | iCal feed token | Static non-rotating token in URL. Add rotation mechanism. | Low priority |
| M4 | Backup access | Any authenticated user can dump all data. Add admin check. | 30 min |
| M5 | Migrate endpoint | No schema validation on import. Add field validation. | 1-2 hrs |
| M6 | Error message leakage | Supabase errors returned to client. Genericize. | 1 hr |

### LOW Priority

| ID | Issue | Description | Effort |
|---|---|---|---|
| L1 | Input validation | No server-side validation on POST endpoints. Add joi/zod. | 2-3 hrs |
| L3 | Auth in localStorage | Move to httpOnly cookies for token storage. | 2-3 hrs |
| L5 | No request logging | Add morgan for access logs and audit trail. | 15 min |

---

## Environment Variables

```env
# Required
SUPABASE_URL=https://xxx.supabase.co
SUPABASE_SERVICE_KEY=eyJ...
GEMINI_API_KEY=AI...

# Security
ALLOWED_ORIGINS=http://localhost:3000,https://yourdomain.railway.app
CALENDAR_FEED_TOKEN=your-secret-token

# Optional
PORT=3000
```

---

## Dependencies Added
- `helmet` — Security headers middleware
- `express-rate-limit` — Request rate limiting
