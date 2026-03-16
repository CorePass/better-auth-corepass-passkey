# CorePass Passkey Plugin for Better Auth

Better Auth plugin that adds **CorePass enrichment** on top of [@better-auth/passkey](https://better-auth.com/docs/plugins/passkey): signed identity and profile data (Core ID, email, age/kyc flags) sent from the CorePass app after passkey registration, with Ed448 signature verification and optional gating (requireO18y, requireO21y, requireKyc).

Use this plugin **after** the passkey plugin. It registers the `corepass_profile` schema and endpoints under your auth base path: **HEAD** and **POST** `/webauthn/data` only.

## Flow overview

1. **Registration** – User starts passkey registration via Better Auth (passkey plugin). Email can come from a **form** (request body of `POST /sign-in/anonymous`, e.g. `signIn.anonymous({ email })`) and/or from **enrichment** later; enrichment overwrites when provided. If `requireRegistrationEmail` is true, a valid email is required in the request body **before** the account is created (otherwise the request is rejected). If `requireEmail` is true, email is required from enrichment only. If `requireAtLeastOneEmail` is true, email must be provided from at least one source. All emails are validated by regex. Default for all three is false.
2. **Finalize** – With `finalize: 'immediate'` the user is active right away. With `finalize: 'after'` (default) the user stays on hold until enrichment is received.
3. **Enrichment** – The CorePass app sends a signed payload to **POST** `{basePath}/webauthn/data` (path `/webauthn/data`; full path e.g. `/auth/webauthn/data` when basePath is `/auth`). The plugin verifies the Ed448 signature over canonical JSON, then:
   - Finds the passkey by `credentialId`, loads the linked user
   - Validates Core ID (ICAN) with [blockchain-wallet-validator](https://github.com/sergical/blockchain-wallet-validator) (Core/ICAN); if invalid or network not in `allowNetwork`, user and sessions are deleted and an error is returned
   - Enforces `requireO18y` / `requireO21y` / `requireKyc` from `userData` if set
   - Updates user email when provided (enrichment overwrites any form/placeholder email), and user name from Core ID (first 4 + "…" + last 4 chars, uppercase)
   - Upserts `corepass_profile` (coreId, o18y, o21y, kyc, kycDoc, `providedTill` from `dataExp` in minutes)
   - Sets the passkey’s display name to Core ID (uppercased)
4. **Profile** – The plugin **extends the official Better Auth get-session response**: when the user has a `corepass_profile` and it is not expired (`providedTill >= now`), the session’s `user` object includes `user.profile` (coreId, o18y, o21y, kyc, kycDoc, backedUp, providedTill). No separate profile endpoint: use `authClient.getSession()` (or your server’s session fetch) to get the profile.
5. **Data expiry** – If `userData.dataExp` (minutes) is set, the plugin stores `providedTill = now + dataExp * 60`. When expired, `user.profile` is omitted from get-session.

### Strict “passkey-only access” (anonymous bootstrap)

The plugin always enforces **passkey-only access**: users without at least one passkey are blocked from auth endpoints except public behaviour (safe methods and passkey registration routes). This is intended for **anonymous bootstrap** flows (e.g. Better Auth anonymous plugin): the app can sign in anonymously, but the account cannot be used until the user registers a passkey.

1. App signs in anonymously (or creates a session without a passkey).
2. Only public behaviour is allowed until the user has a passkey: safe methods (GET, HEAD, OPTIONS) and passkey registration routes (`/passkey/generate-register-options`, `/passkey/verify-registration`). No other routes (e.g. `/webauthn/data`, `/sign-out`) unless you add them via `allowRoutesBeforePasskey`.
3. User must add a passkey (scan/add to device); most complete this within a few minutes.
4. Once the user has at least one passkey, normal access to all auth endpoints is allowed.

**Timeout and cleanup:** Set `deleteAccountWithoutPasskeyAfterMs` (e.g. `300_000` for 5 minutes). If the user does not add a passkey within that time, the next request deletes the account and sessions and returns **403** with code `REGISTRATION_TIMEOUT`. The client can show "Registration timed out. Please start again." and let the user retry from step 1.

This is **not** “anonymous access” to the app; it is **passkey-only access** after an optional anonymous bootstrap. No email/password sign-up is introduced.

**Anonymous user email:** The client can send a user-defined email in the request body of `POST /sign-in/anonymous` (e.g. `signIn.anonymous({ email: formEmail })`). The plugin applies it to the user after the anonymous account is created (enrichment email, when provided later, overwrites it). If no form email is sent, the Better Auth anonymous plugin may set a generated placeholder; enrichment can overwrite that when provided. All emails are validated by regex.

## Sequence diagram (registration + enrichment)

```mermaid
sequenceDiagram
    participant User
    participant Portal
    participant BetterAuth as Better Auth (passkey + corepass-passkey)
    participant CorePass as CorePass app

    User->>Portal: Start registration
    Portal->>BetterAuth: Passkey registration (e.g. add passkey)
    BetterAuth->>User: WebAuthn create prompt
    User->>BetterAuth: Credential created
    BetterAuth->>BetterAuth: Create/update user + passkey

    alt finalize 'immediate'
        BetterAuth->>Portal: User active
    else finalize 'after' (default)
        BetterAuth->>Portal: User on hold (pending enrichment)
    end

    CorePass->>CorePass: User completes identity in CorePass
    CorePass->>CorePass: Sign payload (Ed448, canonical JSON)
    CorePass->>BetterAuth: POST {basePath}/webauthn/data (body + X-Signature, optional X-Public-Key, optional X-Algorithm)
    BetterAuth->>BetterAuth: Verify signature, validate timestamp
    BetterAuth->>BetterAuth: Check requireO18y / requireO21y / requireKyc
    BetterAuth->>BetterAuth: Update user (email), upsert corepass_profile, set passkey name = Core ID
    BetterAuth->>CorePass: 200 OK (X-Algorithm: ed448 or request value)

    User->>Portal: Use app (session)

    Note over User,CorePass: Restore flow (finalize 'after' only): lost device → POST /webauthn/restore/init → QR → CorePass signs → POST /webauthn/restore → POST /webauthn/restore/complete → new passkey
```

## Endpoints

Path is **`/webauthn/data`**. The **plugin owns this route**: in your app’s handle/hooks call **`handlePasskeyDataRoute(request, { handler: auth.handler, basePath })`** (exported from this package). When the request is for `/webauthn/data` or `/webauthn/restore/*`, it returns the response (so you return it and skip basePath); otherwise it returns `null` and you continue to your normal handler. Other auth stays under your basePath (e.g. `/auth`). Plugin default basePath is `/api/auth`.

| Method | Path | Description |
| --- | --- | --- |
| **HEAD** | `/webauthn/data` | **Only method to verify if the endpoint is active.** **200** if enrichment flow is available (`finalize: 'after'`), **404** if not (`finalize: 'immediate'`). Use to detect whether the CorePass app should send enrichment. Do not use GET for this. No `X-Algorithm` header. |
| **POST** | `/webauthn/data` | **Receive data from the application (CorePass) for verification.** Body + `X-Signature` (Ed448). Optional request header `X-Algorithm`; response includes `X-Algorithm` (see [Algorithm](#algorithm-for-post-webauthndata)). Verifies signature, applies options, stores profile, updates user email and passkey name. |
| **POST** | `/webauthn/restore/init` | **Browser** starts passkey restore flow. **Available only when `finalize: 'after'`.** Returns `{ restoreId, expiresAt, signaturePath }`. |
| **POST** | `/webauthn/restore` | **CorePass** sends Ed448-signed `{ coreId, restoreId, timestamp }`. Verifies signature, deletes old passkeys and sessions. |
| **POST** | `/webauthn/restore/complete` | **Browser** polls/calls to exchange verified restoreId for a session cookie. Returns `{ ok: false, status: 'pending' }` while waiting, `{ ok: true, status: 'completed' }` when done. |

**Profile (CorePass data)** is not a separate endpoint. The plugin extends the **official Better Auth get-session** response: call `getSession()` (client or server); when the user has an unexpired CorePass profile, `user.profile` is present with `coreId`, `o18y`, `o21y`, `kyc`, `kycDoc`, `backedUp`, `providedTill`. Type: `CorePassProfile` (exported from this package).

## POST /webauthn/data: payload and signature

- **Body** (JSON): `coreId`, `credentialId`, `timestamp` (Unix **microseconds**), optional `userData`.
- **Headers**: `X-Signature` (required, Ed448), optional `X-Public-Key` (57-byte key when using short-form Core ID), optional `X-Algorithm` (see [Algorithm](#algorithm-for-post-webauthndata)).

**Signature input** (what CorePass signs):

```text
"POST" + "\n" + signaturePath + "\n" + canonicalJsonBody
```

- `signaturePath` defaults to `/webauthn/data` (configurable via `signaturePath`).
- `canonicalJsonBody`: object keys sorted alphabetically, JSON stringified with no extra whitespace.

### Algorithm for POST /webauthn/data

Signature verification is performed with **Ed448**; that is the only algorithm currently supported for the request body. The server does **not** return an algorithm header on **HEAD** `/webauthn/data`. On **POST** `/webauthn/data` only, the response includes an **`X-Algorithm`** header:

- The client may send **`X-Algorithm`** in the request (e.g. `ed448` or `ed25519`). If the value is missing, empty, or not in the allowed set, the server uses **`ed448`**.
- The response header **`X-Algorithm`** is set to that resolved value (request value if valid, otherwise `ed448`). Allowed values are currently **`ed448`** (case-insensitive). **Only ed448 is used for signature verification** at this time.

**userData** (all optional): `email`, `o18y`, `o21y`, `kyc`, `kycDoc`, `dataExp` (minutes → stored as `providedTill`), `backedUp` (boolean: CorePass backed up, not passkey). Email: validated with regex (`local@domain.tld`, max 254 chars). Use `requireEmail` to require it in the payload only; `requireRegistrationEmail` to require the form email at registration; `requireAtLeastOneEmail` to require email from registration or enrichment (enrichment overwrites; non-verified registration email allowed). Core ID is validated as a Core (ICAN) address; invalid IDs or network not in `allowNetwork` cause the user and sessions to be deleted and **400** `CORE_ID_INVALID` or `CORE_ID_NETWORK_NOT_ALLOWED`. If `requireO18y` / `requireO21y` / `requireKyc` are set, the plugin rejects when the flag is not `true`. If `allowOnlyBackedUp` is true, `userData.backedUp` must be present and true or the plugin deletes the user and sessions and returns **400** `BACKED_UP_REQUIRED`. After signature verification, if data is invalid or any required check fails, the plugin **deletes that user and their sessions** and then returns an error.

## Passkey restore (lost phone / new device)

When a user loses their passkey (phone lost, changed, or passkey accidentally deleted), they can prove identity via CorePass Ed448 signature and register a new passkey. No re-enrichment needed — the existing `corepass_profile` is preserved. **Restore is available only when `finalize: 'after'`** (recent behaviour: with `finalize: 'immediate'` the restore endpoints are not offered).

### Restore flow

```mermaid
sequenceDiagram
    participant Browser
    participant Backend as Better Auth (corepass-passkey)
    participant CorePass as CorePass app

    Browser->>Backend: POST /webauthn/restore/init
    Backend->>Browser: { restoreId, expiresAt, signaturePath }
    Browser->>Browser: Show QR (restoreId + signaturePath)
    Note over Browser,CorePass: User scans QR in CorePass
    CorePass->>CorePass: Sign { coreId, restoreId, timestamp } (Ed448)
    CorePass->>Backend: POST /webauthn/restore (X-Signature)
    Backend->>Backend: Verify Ed448, find user by coreId, delete passkeys & sessions
    Backend->>CorePass: { ok: true }
    Browser->>Backend: POST /webauthn/restore/complete (poll)
    Backend->>Browser: { ok: true, status: 'completed' } + session cookie
    Browser->>Backend: Normal passkey registration (add new passkey)
    Note over Browser,Backend: No re-enrichment; corepass_profile preserved
```

### Restore signature

CorePass signs the restore payload the same way as enrichment:

```text
"POST" + "\n" + restoreSignaturePath + "\n" + canonicalJson({ coreId, restoreId, timestamp })
```

- `restoreSignaturePath` defaults to `/webauthn/restore` (configurable via `restoreSignaturePath`).
- `timestamp` is Unix **microseconds** (same as enrichment).

### Restore options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `restoreSignaturePath` | `string` | `/webauthn/restore` | Path used in signature input. |
| `restoreChallengeExpiryMs` | `number` | `300000` (5 min) | How long a restore challenge is valid. |

### Routing

Add restore paths to `handlePasskeyDataRoute` — it already handles `/webauthn/restore/*` automatically alongside `/webauthn/data`. No additional routing setup needed.

## Installation and setup

1. Install after [@better-auth/passkey](https://better-auth.com/docs/plugins/passkey):

   ```bash
   npm install better-auth-corepass-passkey
   ```

2. Add the plugin **after** passkey in your Better Auth config:

   ```ts
   import { betterAuth } from 'better-auth';
   import { passkey } from '@better-auth/passkey';
   import { corepassPasskey } from 'better-auth-corepass-passkey';

   export const auth = betterAuth({
     // ...
     plugins: [
       passkey({ /* rpID, rpName, origin, ... */ }),
       corepassPasskey({
         requireEmail: true,
         finalize: 'immediate', // or 'after' (default): user on hold until enrichment
         signaturePath: '/webauthn/data',
         timestampWindowMs: 600_000,
         requireO18y: false,
         requireO21y: false,
         requireKyc: false,
       }),
       // ...
     ],
   });
   ```

   **Example: anonymous bootstrap + passkey-only access**

   Use with the [anonymous](https://better-auth.com/docs/plugins/anonymous) plugin so users can get a session first, then must register a passkey to access the rest of the app:

   ```ts
   import { betterAuth } from 'better-auth';
   import { anonymous } from 'better-auth/plugins';
   import { passkey } from '@better-auth/passkey';
   import { corepassPasskey } from 'better-auth-corepass-passkey';

   export const auth = betterAuth({
     basePath: '/auth',
     plugins: [
       anonymous(),
       passkey({ rpID: 'your-domain.com', rpName: 'My App', origin: 'https://your-domain.com' }),
       corepassPasskey({
         deleteAccountWithoutPasskeyAfterMs: 300_000,
         finalize: 'after',
         // ... other options
       }),
     ],
   });
   ```

   Use **endpoint paths without basePath**: e.g. `/webauthn/data`, not `/auth/webauthn/data`. The auth router sees paths relative to itself, so the plugin matches `/webauthn/data`. You only need to set `allowPasskeyRegistrationRoutes` if you use custom passkey paths; the default already allows the standard passkey plugin routes so registration and login work without extra config.

3. Run migrations so the `corepass_profile` table exists (see [Schema](#schema)).

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `finalize` | `'immediate' \| 'after'` | `'after'` | When the user becomes active: `'immediate'` right after passkey registration; `'after'` when enrichment is received. |
| `signaturePath` | `string` | `'/webauthn/data'` | Path used when building the signature input string. |
| `timestampWindowMs` | `number` | `600_000` | Allowed clock skew for `timestamp` (microseconds). |
| `requireEmail` | `boolean` | `false` | Require email **in enrichment payload only** (userData.email in POST /webauthn/data). Validated by regex. On failure after signature verification, user and sessions are deleted. |
| `requireRegistrationEmail` | `boolean` | `false` | Require valid email in the **request body** of POST /sign-in/anonymous (e.g. `signIn.anonymous({ email })`) **before** the account is created. If missing or invalid, request is rejected (**400**). If user has passkey but still no valid email, account is cleaned and **403** `EMAIL_REQUIRED`. |
| `requireAtLeastOneEmail` | `boolean` | `false` | Require email from at least one source: registration (form body) or enrichment. Enrichment overwrites when provided. All validated by regex. If neither provided, fail and clean (enrichment) or **403** and clean (access). |
| `requireO18y` | `boolean` | `false` | Reject enrichment if `userData.o18y` is not true. On failure (after signature verification), the user and sessions are deleted. |
| `requireO21y` | `boolean` | `false` | Reject enrichment if `userData.o21y` is not true. On failure (after signature verification), the user and sessions are deleted. |
| `requireKyc` | `boolean` | `false` | Reject enrichment if `userData.kyc` is not true. On failure (after signature verification), the user and sessions are deleted. |
| `allowNetwork` | `('mainnet' \| 'testnet' \| 'enterprise')[] \| true \| false` | `['mainnet', 'enterprise']` | Which Core (ICAN) networks to allow in enrichment. Array of allowed networks, or `true` (= mainnet only), or `false` (= testnet only). If Core ID's network is not in the list, user/sessions are deleted and **400** `CORE_ID_NETWORK_NOT_ALLOWED`. |
| `allowOnlyBackedUp` | `boolean` | `false` | When true, require `userData.backedUp` to be present and true in enrichment (CorePass backed up). If not, user/sessions are deleted and **400** `BACKED_UP_REQUIRED`. |
| `allowedAaguids` | `string \| string[] \| false` | Core Pass AAGUID `636f7265-7061-7373-6964-656e74696679` | AAGUID allowlist for passkey registration. Default restricts to Core Pass. Use a string (one), string[] (many), or `false` to allow any authenticator. Enforced via passkey `create.before` DB hook. |
| `allowRoutesBeforePasskey` | `string[]` | `[]` | Routes allowed when user has no passkey (in addition to safe methods and passkey registration). Add paths only if needed. |
| `allowMethodsBeforePasskey` | `string[]` | `['GET', 'HEAD', 'OPTIONS']` | HTTP methods always allowed before first passkey (e.g. session fetch). |
| `allowPasskeyRegistrationRoutes` | `string[]` | `['/passkey/generate-register-options', '/passkey/verify-registration']` | Only needed if you use custom passkey paths. Default already allows registration; leave unset otherwise. |
| `deleteAccountWithoutPasskeyAfterMs` | `number` | `300_000` (5 min) | Accounts with no passkey after this many ms since creation are deleted on next request (sessions + user). Response **403** with code `REGISTRATION_TIMEOUT`. Set to 0 to disable. |

Only **anonymous registration** can be restarted: when a user with no passkey POSTs to **`/sign-in/anonymous`** ([anonymous plugin](https://www.better-auth.com/docs/plugins/anonymous)), the plugin deletes that user/sessions and returns so the handler can create a new one. The same user can therefore start over by calling sign-in anonymous again. **Sign-in is not reset** (email, OAuth, etc.). For email/password or OAuth accounts without a passkey, the plugin does not offer restart; the user gets **403** `REGISTRATION_TIMEOUT` after `deleteAccountWithoutPasskeyAfterMs` and should be told to wait for expiration and retry.

### Better Auth paths this plugin uses or allows

| Path | Method | Behaviour |
| --- | --- | --- |
| `/sign-in/anonymous` | POST | **Restart registration** (anonymous only): delete current user/sessions so handler can create a new one. |
| `/passkey/generate-register-options`, `/passkey/verify-registration` | POST | Allowed before passkey (passkey plugin). |
| `/webauthn/data` | HEAD, POST | HEAD = verify if active; POST = receive data from application (CorePass) for verification. |
| `/get-session` | GET | Allowed (safe method). |

Other paths (e.g. `/sign-up/email`, `/sign-in/email`, OAuth callbacks, `/sign-out`) are not restarted; if the user has no passkey they are blocked (or timeout) and the client should show "wait for expiration and retry" where applicable.

## Schema

The plugin adds a `corepass_profile` model. Example migration (adjust for your DB):

```sql
CREATE TABLE "corepass_profile" (
  "userId" TEXT NOT NULL REFERENCES "user"("id") ON DELETE CASCADE PRIMARY KEY,
  "coreId" TEXT NOT NULL,
  "o18y" INTEGER NOT NULL,
  "o21y" INTEGER NOT NULL,
  "kyc" INTEGER NOT NULL,
  "kycDoc" TEXT,
  "backedUp" INTEGER,
  "providedTill" INTEGER
);
CREATE INDEX "corepass_profile_userId_idx" ON "corepass_profile"("userId");
```

**Note:** `backedUp` here is **CorePass app** backup (passphrase), not the passkey plugin’s `backedUp` (credential sync). Different tables and semantics; no collision.

The plugin also adds a `restore_challenge` table for passkey recovery:

```sql
CREATE TABLE "restore_challenge" (
  "id" TEXT NOT NULL PRIMARY KEY,
  "userId" TEXT,
  "status" TEXT NOT NULL,
  "expiresAt" INTEGER NOT NULL,
  "createdAt" INTEGER NOT NULL
);
```

Run your Better Auth schema generation / migrations so these tables exist.

Better Auth and the passkey plugin manage WebAuthn challenge expiry via their own storage and TTLs. Registrations that never receive enrichment (e.g. user abandons after passkey create) remain as users with a passkey but no `corepass_profile`. You can expire or delete them manually (e.g. by age using `user.createdAt` and absence of `corepass_profile`) if needed.

## Client

Optional client plugin (no extra methods; enrichment is server-side):

```ts
import { createAuthClient } from 'better-auth/svelte';
import { passkeyClient } from '@better-auth/passkey/client';
import { corepassPasskeyClient } from 'better-auth-corepass-passkey/client';

export const authClient = createAuthClient({
  baseURL: 'https://your-app.com',
  plugins: [passkeyClient(), corepassPasskeyClient()],
});
```

## Test plan (passkey-only access)

Minimal cases to verify the strict passkey-only flow:

1. **Anonymous session, zero passkeys → protected route denied**
   Sign in anonymously, call a protected auth endpoint (e.g. `/get-session` with POST or an endpoint that is not in the allowed list for the method). Expect **403** with body `code: 'PASSKEY_REQUIRED'`.

2. **Anonymous session, zero passkeys → passkey registration route allowed**
   Same session; call `/passkey/generate-register-options` or `/passkey/verify-registration` (and complete registration). Expect **200** (or normal flow).

3. **After passkey registration → protected route allowed**
   With the same user now having one passkey, call the previously blocked endpoint. Expect **200** (or normal response).

4. **Verify /webauthn/data active → HEAD /webauthn/data**
   Call HEAD `/webauthn/data`. With `finalize: 'after'` expect **200**; with `finalize: 'immediate'` expect **404**. Do not use enrichment for this.

## References

- [Better Auth – Passkey](https://better-auth.com/docs/plugins/passkey)
- [CorePass](https://corepass.net/)

## License

Licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
