# Frickmail OAuth2 — Application Registration Guide

Frickmail can sign users in to **Gmail** and **Office 365 / Outlook.com**
mailboxes through OAuth2 — exactly like Thunderbird. The end user only types
their email address; a popup opens the provider's consent screen and the
mailbox is unlocked once consent is granted. No password is ever stored.

To make this work, you (the operator running the Frickmail server) need to
register an OAuth2 **client application** with Google and/or Microsoft so
they know about your Frickmail instance. This page walks through both
registrations, then shows how to plug the resulting credentials into
Frickmail.

> Frickmail uses **PKCE** (RFC 7636), so for both providers a
> `client_secret` is **optional**. A public client_id alone is enough — set
> the secret only if your registration type requires one.

---

## 1. Decide your redirect URIs

Replace `https://mail.example.com` below with the public URL of your
Frickmail deployment. Trailing slashes matter — copy these exactly.

| Provider                            | Redirect URI                                  |
| ----------------------------------- | --------------------------------------------- |
| Gmail (any Google account)          | `https://mail.example.com/?LoginGMail`        |
| Office 365 (work / school accounts) | `https://mail.example.com/?LoginO365`         |
| Outlook.com (personal accounts)     | `https://mail.example.com/LoginO365`          |

The Gmail and Office 365 URIs use a query string; the personal-Outlook URI
does **not**, because Microsoft's consumer endpoint rejects query parameters
in the redirect URI. If you support both worlds, register both URIs on the
Microsoft side.

---

## 2. Register the application with Google (Gmail)

1. Open the [Google Cloud Console](https://console.cloud.google.com/) and
   create or pick a project.
2. Enable the **Gmail API** under *APIs & Services → Library*.
3. Configure the **OAuth consent screen** under *APIs & Services → OAuth
   consent screen*:
   - User type: **External** (unless you only serve Workspace users).
   - App name: `Frickmail` (or whatever you want users to see).
   - Authorised domains: the public domain of your Frickmail server
     (e.g. `example.com`).
   - Scopes (add the following on the Scopes page):
     - `openid`
     - `https://www.googleapis.com/auth/userinfo.email`
     - `https://www.googleapis.com/auth/userinfo.profile`
     - `https://mail.google.com/`
   - Add yourself as a **test user** while the consent screen is in
     *Testing* state. Submit it for verification only when you are ready
     for the public.
4. Create credentials under *APIs & Services → Credentials → Create
   credentials → OAuth client ID*:
   - Application type: **Web application**.
   - Authorised redirect URI: `https://mail.example.com/?LoginGMail`.
5. Copy the resulting **Client ID** (and Client Secret if Google issued
   one). You will plug these into Frickmail in step 4.

---

## 3. Register the application with Microsoft (Office 365 / Outlook.com)

1. Sign in to the
   [Microsoft Entra ID portal](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps)
   with an admin account of your tenant.
2. *App registrations → New registration*:
   - Name: `Frickmail`.
   - Supported account types:
     - **Accounts in this organizational directory only** if you only
       host work/school accounts in your tenant.
     - **Accounts in any organizational directory and personal Microsoft
       accounts** if you also want Outlook.com / Hotmail to work.
   - Redirect URI: pick **Web** and enter
     `https://mail.example.com/?LoginO365`.
   - After creation, open *Authentication* and add a second redirect URI
     `https://mail.example.com/LoginO365` if you also enabled personal
     accounts.
3. *API permissions → Add a permission → APIs my organization uses* and
   search for **Office 365 Exchange Online**. Add the following
   *Delegated* permissions:
   - `IMAP.AccessAsUser.All`
   - `SMTP.Send`
   Then add from **Microsoft Graph** the *Delegated* permissions:
   - `openid`
   - `email`
   - `profile`
   - `offline_access`
   - `User.Read`
   Click **Grant admin consent** if your tenant requires it.
4. *Authentication → Advanced settings*:
   - **Allow public client flows: Yes** (this is what enables PKCE).
   - **Live SDK support: Yes** (only if personal Microsoft accounts are
     allowed).
5. Optional — *Certificates & secrets → New client secret* to mint a
   client secret. You can skip this entirely if you stick with PKCE.
6. Copy the **Application (client) ID** and the **Directory (tenant) ID**
   from the *Overview* tab.

> Tenant value to use in Frickmail config:
> - `common` — work/school **and** personal accounts.
> - `consumers` — personal Microsoft accounts only (Outlook.com, Hotmail).
> - `organizations` — any work or school account.
> - The **Directory (tenant) ID** GUID — restrict logins to a single
>   tenant.

---

## 4. Configure Frickmail

You can configure credentials in two ways. Frickmail tries the admin UI
first, then falls back to environment variables.

### 4a. Environment variables (recommended for Docker)

Add the following to your `docker-compose.frickmail.yml` (or your shell
environment):

```yaml
services:
  frickmail:
    environment:
      # Gmail
      - FRICKMAIL_GMAIL_CLIENT_ID=1234567890-abc.apps.googleusercontent.com
      - FRICKMAIL_GMAIL_CLIENT_SECRET=                # leave empty for PKCE
      # Office 365 / Outlook
      - FRICKMAIL_O365_CLIENT_ID=00000000-0000-0000-0000-000000000000
      - FRICKMAIL_O365_CLIENT_SECRET=                 # leave empty for PKCE
      - FRICKMAIL_O365_TENANT=common                  # or your tenant GUID
```

### 4b. Admin UI

1. Log in as the Frickmail admin (default URL: `/?admin`).
2. Open *Plugins* and enable both **Login GMail OAuth2** and
   **Office365/Outlook OAuth2**.
3. Click *Configure* on each plugin and fill in:
   - Client ID
   - Client Secret (leave empty for a public PKCE client)
   - Tenant (Office 365 only)
   - Domains — whitespace-separated list of domains that should be routed
     through this provider (e.g. add your Workspace or O365 tenant
     domains here)

---

## 5. End-user experience

- The user opens Frickmail and types their email address.
- If the email matches a configured domain, the password field is bypassed
  and a popup opens the provider's consent screen.
- After granting consent, the popup closes itself and the webmail loads
  the inbox automatically — no further input needed.
- Refresh tokens are stored encrypted in the SnappyMail session so the
  user stays signed in until they log out.

If a user's browser blocks popups, Frickmail falls back to a full-page
redirect to the provider's consent screen.

---

## 6. What if you can't get tenant admin consent?

For corporate Microsoft 365 tenants, the IMAP/SMTP scopes
(`IMAP.AccessAsUser.All`, `SMTP.Send`) require **tenant admin consent** — a
user cannot self-grant them. If you're trying to log into an account in a
tenant where you are not the admin (and the admin won't grant consent for
your Frickmail app registration), OAuth2 cannot be made to work for that
account. Microsoft has no per-user override for these scopes.

You still have three working alternatives:

### 6.1 IMAP with an app-password (recommended)

If the user has multi-factor authentication enabled and the tenant still
allows app passwords (this is common — it's a separate setting from
"Allow OAuth app consent"), the user can:

1. Generate an app password at
   <https://account.microsoft.com/security> (personal) or
   <https://mysignins.microsoft.com/security-info> (work / school) →
   *Add sign-in method → App password*.
2. On the Frickmail login screen, type the email address and click the
   **Use password instead** button (added by the OAuth2 plugin) — this
   skips OAuth for one submission. Paste the app password as the password.
3. SnappyMail will fall back to its standard IMAP login flow, which
   contacts `outlook.office365.com:993` directly with basic auth +
   the app password.

> Tip: if you want this domain to *always* use password auth rather than
> OAuth, just remove the domain from the plugin's *Domains* setting.
> Frickmail will then leave that domain alone and let SnappyMail
> authenticate it the normal way.

### 6.2 Use a multi-tenant app registration

If you can't register an app in the user's tenant but you *can* register
one in any other Entra tenant (your own, for example), set the supported
account types to **multi-tenant + personal Microsoft accounts** when you
register Frickmail. Then set `FRICKMAIL_O365_TENANT=common`. Each user
who logs in is asked to consent in their own tenant — but their tenant
admin will still need to approve before consent can complete, so this
helps only when the target tenant allows user consent for non-Tier-2
scopes.

### 6.3 Personal Microsoft accounts (Outlook.com / Hotmail)

Personal accounts (`@outlook.com`, `@hotmail.com`, `@live.com`, …) never
need admin consent. Set `FRICKMAIL_O365_TENANT=consumers` and the user
can self-consent in the popup. No admin involvement at all.

---

## 7. Troubleshooting

| Symptom                                  | Likely cause                                                                |
| ---------------------------------------- | --------------------------------------------------------------------------- |
| `redirect_uri_mismatch` from Google      | URI in step 1 doesn't match the one registered in the Google Cloud Console. |
| `AADSTS50011` from Microsoft             | Same as above — fix the redirect URI in Entra ID *Authentication*.          |
| `AADSTS65001` (consent required)         | Click *Grant admin consent* in Entra ID *API permissions*.                  |
| `invalid_grant` after consent            | PKCE state cookie was cleared — make sure the Frickmail domain has cookies. |
| Popup opens but never closes             | The browser is blocking `window.opener.postMessage`. Check the JS console.  |
| `imap.authenticationfailed` after login  | The OAuth client is missing the `https://mail.google.com/` (Gmail) or       |
|                                          | `IMAP.AccessAsUser.All` (O365) scope.                                       |

Server-side errors are logged to the SnappyMail log
(`/var/lib/snappymail/_data_/_default_/logs/log-*.txt`) — check there for
the exact OAuth2 response from the provider.
