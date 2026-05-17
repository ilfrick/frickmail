<div align="center">
  <img src="snappymail/v/0.0.0/static/frickmail-icon-source.png" alt="Frickmail" width="120" height="120">
  <h1>Frickmail</h1>
  <p>Self-hosted webmail with Thunderbird-style OAuth2 for Gmail and Office 365, plus contacts &amp; calendar sync.</p>
  <p>
    <a href="docs/OAUTH2.md">OAuth2 setup</a> •
    <a href="SECURITY.md">Security policy</a> •
    <a href="docker-compose.frickmail.yml">Docker compose</a>
  </p>
</div>

---

## Fork notice

Frickmail is a fork of [**SnappyMail**](https://github.com/the-djmaze/snappymail).
All credit for the underlying webmail engine goes to the SnappyMail team.

This repository tracks upstream `master` and adds Frickmail-specific
features without altering the upstream namespaces or core data formats,
so a fresh data directory created by SnappyMail can be reused with
Frickmail and vice versa.

Last upstream sync point: commit `c154d23` (2026-03-11).

## What Frickmail adds on top of SnappyMail

| Plugin / change      | Adds                                                                                  |
| -------------------- | ------------------------------------------------------------------------------------- |
| `login-gmail` (mod)  | PKCE flow, env-var configuration, popup-based consent, configurable Workspace domains |
| `login-o365`  (mod)  | PKCE flow, env-var configuration, popup-based consent, configurable tenant + domains  |
| `contacts-sync`      | Imports contacts from Google People API / Microsoft Graph into the local PAB          |
| `calendar`           | Embedded month-view calendar with create/edit/delete against Google / Graph events    |
| `Use password` button| Lets a user bypass OAuth for one login attempt and use an IMAP app-password instead   |
| Docker image         | Bundles all the above and seeds them on first boot, ready-to-deploy                   |
| Re-branding          | UI title, admin panel and About page rebranded to Frickmail                           |

OAuth2 is the headline feature: end users only type their email, the
provider's consent screen opens in a popup, and they're signed in —
exactly like Thunderbird does it. See **[docs/OAUTH2.md](docs/OAUTH2.md)**
for app-registration steps, including the case where the user does not
have access to a tenant administrator.

## Quick start (Docker)

```bash
docker compose -f docker-compose.frickmail.yml up -d
```

- Webmail: <http://localhost:8888/>
- Admin:   <http://localhost:8888/?admin>
- Admin password (created on first boot):
  ```bash
  docker exec frickmail cat /var/lib/snappymail/_data_/_default_/admin_password.txt
  ```

For OAuth2 you need a public HTTPS URL. Put Frickmail behind Caddy /
Traefik / nginx with Let's Encrypt and register
`https://your-domain/?LoginGMail` and `https://your-domain/?LoginO365` as
the redirect URIs in your Google Cloud / Azure registrations.

## Building from source

The Docker image is a multi-stage build that runs `release.php` over
the upstream SnappyMail source and bundles our plugins on top:

```bash
docker build -f .docker/release/Dockerfile -t frickmail:latest .
```

## License

Frickmail keeps the upstream license: **GNU AGPL v3**.

- Copyright © 2026 Frickmail (Frickmail-specific code)
- Copyright © 2020 - 2024 SnappyMail
- Copyright © 2013 - 2022 RainLoop

See [LICENSE](LICENSE) for full text.

## Acknowledgements

- The [SnappyMail](https://github.com/the-djmaze/snappymail) team for
  building and maintaining the engine this fork rests on.
- The original [RainLoop](https://github.com/RainLoop/rainloop-webmail)
  authors.
- [Sabre/VObject](https://github.com/sabre-io/vobject) for VCard support.

## Security

See [SECURITY.md](SECURITY.md) for the policy. Short version: upstream
issues go to `security@snappymail.eu`, Frickmail-only issues to
[GitHub security advisories](https://github.com/ilfrick/frickmail/security/advisories/new).
