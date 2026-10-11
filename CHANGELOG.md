# Changelog

All notable changes to `agience-origin` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.1] - 2026-10-11

### Added
- The `persons` table gains nullable `deactivated_at` and `deactivated_reason` columns (migration `0007_person_deactivation`, applied at startup). Existing accounts stay active. Downgrading drops both columns, so every deactivated account becomes active again.
- Accounts can be deactivated. A deactivated account cannot sign in through `/auth/password/login`, the local password and one-time-code authorize routes, the authorization-code grant, the `refresh_token` grant on `/auth/token`, or email verification confirmation. Each of these returns a 403 with the same message, `This account is deactivated. Contact support to restore it.`
- `python -m origin.admin person show|deactivate|reactivate <email|username|id>` lets operators manage account state. `deactivate` requires `--reason`. `reactivate` restores the account exactly, and `--restore-password-from FILE` puts back a password hash from a JSON backup of person rows, only for an account that has no password. Password hashes are never printed.

### Changed
- The password routes return 403 only after the correct password is supplied, so only the password's holder learns the account is deactivated. Other credentials get the usual 401.
- A deactivated account is sent no mail. `/auth/otp/request`, `/auth/password/reset-request` and the email verification resend send nothing and give the same reply as for an unknown address. Outstanding password reset links stop working for it.

## [0.2.0] - 2026-10-09

### Breaking

- An email-confirmation link signs in only the browser that started the sign-up, identified by a nonce it holds. A forwarded or nonce-less link still confirms the address but signs nobody in.
- The unauthenticated routes that send mail (one-time codes, confirmation resends, password resets, registration) share one budget per address and per client. Over the budget the response is unchanged and no mail is sent. An IPv6 /64 counts as one client.
- Sign-in requests that spend a key derivation are shed with `503` and `Retry-After` when the queue is deep. One client may hold a bounded number of sign-ins in flight.

### Added

- Every access token that names a person carries `email_verified`, the stored fact about the address, on every sign-in path (password, link, one-time code, passkey, code grant, refresh, setup wizard).
- `APP_URI` sets where the account page's "Continue to Agience" leads (also the `branding.app_uri` setting). Loopback hosts and Origin's own address are refused.
- `SSO_RETURN_URIS` lists the exact https URLs a signed-in visitor is returned to without a click, beyond `APP_URI`'s root (also `branding.sso_return_uris`).
- `SHARED_CLIENT_NETWORKS` lists relays whose requests are many people's; they are exempt from the per-client mail and in-flight caps. Entries must be exact (`a.b.c.d/32` for a host); others are refused with a warning.
- `ORIGIN_KDF_THREADS` sets how many key derivations run at once (default: one fewer than the CPUs available, at least 1).
- The holder of a mailbox can disown a registration they did not make, and an account without a password confirms from the link alone.
- The login refusal for an unconfirmed address carries a machine-readable code.

### Changed

- A one-time-code request is answered the same whether or not the address holds an account, capped or not, and whether or not the mail was sent.
- A password check that does not match costs at least the configured derivation count, whatever the stored hash.
- Request bodies bound the length of identifiers and addresses; an oversized one is refused before it reaches the store.
- Logs name an address or identifier by a keyed tag, never in the clear.
- Key derivations run in a bounded thread pool, so a slow derivation does not stall other requests or database access.
- The account and confirmation pages lead back to the app.
