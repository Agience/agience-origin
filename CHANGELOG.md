# Changelog

All notable changes to `agience-origin` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.8] - 2026-10-12

### Changed
- A password reset link carries a 32-character random token instead of a signed one of about 600 characters. Origin stores only the token's SHA-256, in the new `password_resets` table (migration `0008_password_resets`, applied at startup), with the account, the password fingerprint at sending and the expiry (1 hour). Setting a password through a link deletes every reset link for that account; a link also stops working once the password changes any other way. Links sent before this version stop working.

## [0.2.7] - 2026-10-11

### Added
- `EMAIL_PROVIDER=outbox` sends nothing and writes each message as one JSON file (`to`, `subject`, `text`, `html`, `sent_at`) in `EMAIL_OUTBOX_DIR`, for a test stack to read. Without `EMAIL_OUTBOX_DIR` the provider counts as not configured.

## [0.2.6] - 2026-10-11

### Added
- `GET /logout` ends Origin's session for the browser: it clears the server session, the page clears the stored token, then it returns to the `return` address only when Origin lists it (`app_uri` or an `sso_return_uris` entry), else to Origin's sign-in page. The account page's "Sign out" goes through it.

## [0.2.5] - 2026-10-11

### Added
- `POST /auth/password/reset-check` returns the address of the account a reset link resets, only while the link would still be accepted (signed, unused, unexpired, password unchanged since it was sent).

### Changed
- The password reset link carries no address. The reset page names the account from `reset-check`, so the account shown is always the one the link resets, and an expired or used link says so before a password is typed. The account field is read-only and is never sent to the server.

## [0.2.4] - 2026-10-11

### Added
- Sign-in code, password reset and email verification mails state when and from what they were requested, for example "Requested on 11 Oct 2026 at 15:48 UTC from Chrome on Windows." Browser and system names come only from a set list; nothing a caller sends is copied into the mail.
- The password reset link carries the account's address (`&email=`), and the reset page shows it in a read-only `username` field beside the new password, so a password manager saves the new password under that account.

### Changed
- Every input on the sign-in and reset pages has a `name`, so password managers fill them.

## [0.2.3] - 2026-10-11

### Added
- `email.reply_to` setting sets the `Reply-To` address on outgoing mail; when empty, replies go to the sender address.
- `branding.email_logo_url` setting chooses the logo shown at the top of every email. By default the message uses the 320 px logo this Origin serves at `/web/logo_mail.png`.
- Mail sent through the `email_service` SMTP and Gmail providers now carries `Date` and `Message-ID` headers, the latter on the sender's own domain, and its text and HTML parts are encoded as UTF-8.

### Changed
- Sign-in code, password reset, email verification and invitation messages from `email_service` are complete HTML documents with a preview line, the logo, and a footer saying who sent the message and why. Each has a fuller plain-text version, names the recipient address, and uses new subject lines, for example "Your Agience sign-in code" and "Confirm your email for Agience".
- Invitation emails escape the inviter's name, the resource name and the personal message, so they show as plain text in the HTML.
- Links in emails are escaped inside the HTML and appear whole in the plain-text version.

## [0.2.2] - 2026-10-11

### Changed
- `origin.admin` person output (`person show`, `person reactivate` and related commands) now reports the password hash's algorithm and cost, such as `password=pbkdf2_sha256/600000`, in place of `password=set`. It shows `none` when no password is set and `unreadable` for a hash that cannot be parsed. The hash itself is never printed.
- `origin.admin` person output now includes a `modified=` field with the person's last modified time, or `-` when none is recorded.

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
