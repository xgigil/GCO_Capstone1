# Google OAuth Security Issue

**Date:** 2026-11-12  
**Related audit:** [Non-XU email login bypass review](#audit-check-non-xu-login-bypass)  
**Status:** Findings #3 and #5 addressed; #4 (`hd`) still optional / unset; #6 (`/signup-disabled`) already absent — see [audit findings table](#findings-severity)

## Summary

Hardened XU email domain checks (exact domain instead of `endsWith`) across login and admin user-create, shared via a util module with dedicated tests. Also require Google’s **verified** email flag in Passport before accepting a Google sign-in.

---

## Audit check (non-XU login bypass)

**Date of audit:** 2026-11-12  
**Goal:** Find ways a non-`@my.xu.edu.ph` / `@xu.edu.ph` identity could still authenticate or be created despite existing domain gates.  
**Scope reviewed:** password login (`auth.js`), Google OAuth (`oauth.js`, `passport.js`, `roles.js`), admin user create (`admin.js`), JWT middleware (`middleware/auth.js`), CSV/Sheets import (`import.js`, `sheets.js`), signup paths, `.env` secrets.

### What the audit concluded

Normal UI login for a casual `@gmail.com` user was **already blocked** on the main paths (Google domain allowlist, student Google-only, counselor/admin domain check). The real issues were **weaker string checks**, **defense-in-depth gaps**, and **side paths** that could create or impersonate identities without a real XU Workspace mailbox.

### Findings (severity)

| # | Severity | Finding | Result after this update |
|---|----------|---------|---------------------------|
| 1 | Critical | Weak / placeholder `JWT_SECRET`; forged JWT bypasses email rules (`requireAuth` does not re-check domain/DB) | **Fixed in .env** |
| 2 | High | CSV / Sheets import can create **any** email as an active, verified user | **Still open** |
| 3 | High | Domain check used `endsWith` (suffix tricks), not exact domain; admin create lagged behind | **Fixed** — see [Finding #3](#finding-3--domain-check-was-suffix-only-endswith) |
| 4 | Medium | Google `hd` (hosted domain) unset → any Google account can hit consent; reject only later in Passport | **Not fixed** — see [Finding #4](#finding-4--google-hd-hosted-domain--not-closed-by-code-in-this-update) |
| 5 | Medium | Passport did not require Google’s email `verified` flag | **Fixed** — see [Finding #5](#finding-5--google-email-verified-flag-not-checked) |
| 6 | Medium | Live `/signup-disabled` could create staff rows (easy local verify via MailHog) | **Already absent** — see [Finding #6](#finding-6--apiauthsignup-disabled) |

### What still blocked non-XU interactive login (at audit time)

| Path | Non-XU (`@gmail.com`) |
|------|------------------------|
| Student Google OAuth | Rejected by `isAllowedGoogleDomain` |
| Student password | Hard-blocked (Google-only) |
| Counselor/admin password | Rejected by role domain check |
| Admin create user | Rejected unless email matched role domain (then weakly via `endsWith`) |

### Takeaway

The audit was **not** “Gmail can log in through the UI today,” but “string/`endsWith` checks, missing Google verified email, optional `hd`, import paths, and JWT forgery can weaken or bypass the *intent* of XU-only access.” This changelog records the domain + Google-verified fixes; JWT hardening and import domain refusal remain follow-ups.

---

## Files

| Path | Change |
|------|--------|
| `server/utils/emailDomain.js` | **Added** — shared exact-domain helpers |
| `server/routes/auth.js` | **Modified** — uses shared helpers on password login |
| `server/routes/admin.js` | **Modified** — admin create-user uses same helpers (no more `endsWith`) |
| `tests/email-domain-auth-tests.js` | **Added** — tests for normalize / domain / role rules |
| `server/config/passport.js` | **Modified** — require Google-verified email before domain check |

---

## Finding #3 — Domain check was suffix-only (`endsWith`)

### Before

`matchesRoleDomain` used `email.toLowerCase().endsWith("@xu.edu.ph")` / `@my.xu.edu.ph`.  
That allowed suffix tricks such as:

- `user@evilxu.edu.ph`
- `user@gmail.com@xu.edu.ph`
- `user@mail.xu.edu.ph` (wrong host, still “ends with” in some weak forms)

`admin.js` still used its own `endsWith` helper, so login and admin create-user could disagree.

```js
// OLD (auth.js / admin.js)
function matchesRoleDomain(email, role) {
  const required = getRequiredDomainByRole(role);
  if (!required) return false;
  return email.toLowerCase().endsWith(`@${required}`);
}
```

### After

Exact mailbox-domain match after normalize:

- Student → domain must be exactly `my.xu.edu.ph`
- Counselor / admin → domain must be exactly `xu.edu.ph`
- Rejects multiple `@`, invalid syntax, and suffix lookalikes

#### Added: `server/utils/emailDomain.js`

```js
function getRequiredDomainByRole(role) {
  if (role === "student") return "my.xu.edu.ph";
  if (role === "counselor" || role === "admin") return "xu.edu.ph";
  return null;
}

const EMAIL_RE =
  /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/;

function normalizeEmail(raw) {
  if (typeof raw !== "string") return null;
  const email = raw.trim().toLowerCase();
  if (email.length > 254 || !EMAIL_RE.test(email)) return null;
  return email;
}

function getEmailDomain(email) {
  const at = email.indexOf("@");
  if (at < 1 || at !== email.lastIndexOf("@")) return null;
  return email.slice(at + 1);
}

function matchesRoleDomain(rawEmail, role) {
  const required = getRequiredDomainByRole(role);
  if (!required) return false;
  const email = normalizeEmail(rawEmail);
  if (!email) return false;
  return getEmailDomain(email) === required.toLowerCase();
}

module.exports = {
  getRequiredDomainByRole,
  normalizeEmail,
  getEmailDomain,
  matchesRoleDomain
};
```

#### Modified: `server/routes/auth.js`

- Imports helpers from `../utils/emailDomain`
- Login runs `matchesRoleDomain` + `normalizeEmail` before DB lookup

#### Modified: `server/routes/admin.js`

- Removed local `endsWith`-based helpers
- `POST /users` uses `normalizeEmail` + `matchesRoleDomain` and stores `normalizedEmail`

#### Added: `tests/email-domain-auth-tests.js`

Labeled coverage for the new exact-domain rules (allow real XU addresses; block Gmail, suffix tricks, multi-`@`, wrong role domains).

---

## Finding #5 — Google email `verified` flag not checked

### Before

Passport took the first email Google returned, with no verified check:

```js
const rawEmail = profile.emails?.[0]?.value;
if (!rawEmail) {
  return done(null, false, { message: "Google did not return an email address." });
}
const email = String(rawEmail).trim().toLowerCase();
```

### After (`server/config/passport.js`)

Only accept an email Google marks as verified; then keep the XU domain allowlist.

```js
function isTrue(v) {
  return v === true || v === "true";
}
function isFalse(v) {
  return v === false || v === "false";
}

// In Google strategy verify callback:
const emails = Array.isArray(profile.emails) ? profile.emails : [];
const picked = emails.find((e) => e && e.value && isTrue(e.verified)) || null;
if (!picked) {
  return done(null, false, { message: "Google did not return a verified email address." });
}
if (profile._json && isFalse(profile._json.email_verified)) {
  return done(null, false, { message: "Google email is not verified." });
}

const email = String(picked.value).trim().toLowerCase();
// then isAllowedGoogleDomain(email) → create/link user as before
```

**Meaning:** “Verified” = Google confirmed ownership of that address (not the app’s password-signup `email_verified` column). Normal XU Workspace accounts are typically verified.

---

## Finding #6 — `/api/auth/signup-disabled`

### Before (audit)

Public `/signup` disabled, but `/signup-disabled` could still create counselor/admin rows for addresses that passed domain checks (easy to “verify” locally via MailHog).

### After (current tree)

- No `signup-disabled` route
- `POST /auth/signup` returns **403** (admin must create staff from Users panel)

No file delete was required in this pass if the route was already gone; document as **confirmed removed / not present**.

---

## Finding #4 — Google `hd` (hosted domain) — not closed by code in this update

### Current behavior

Unless `GOOGLE_OAUTH_HOSTED_DOMAIN` is set to a non-empty value, `oauth.js` leaves `hd` null (any Google account can reach consent; server still rejects non-XU via `isAllowedGoogleDomain`).

### Note for dual domains

Students use `@my.xu.edu.ph`, faculty/staff `@xu.edu.ph`. Google `hd` accepts **one** domain per request. For student-only Google login, `GOOGLE_OAUTH_HOSTED_DOMAIN=my.xu.edu.ph` is viable; when faculty share the student role later, prefer dynamic `hd` or leave unset and rely on server checks.

---

## Still open from the same audit (not part of this changelog)

1. Weak / placeholder `JWT_SECRET` and no post-verify DB/domain reload in `requireAuth` — see [audit findings](#findings-severity) (#1)
2. CSV / Sheets import can still create non-XU emails as users (`import.js` / `sheets.js`) — see [audit findings](#findings-severity) (#2)

---

## Why these changes matter

| Layer | What it does |
|-------|----------------|
| Exact domain helpers | Stops “looks like XU” suffix tricks on login and admin create |
| Shared util | One rule for auth + admin |
| Tests | Locks the new domain behavior |
| Google `verified` | Only trust emails Google confirms before XU domain allowlist |

Casual `@gmail.com` interactive login remains blocked; these fixes close the weaker string/OAuth-profile gaps called out in the [audit check](#audit-check-non-xu-login-bypass).