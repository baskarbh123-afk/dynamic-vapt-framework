# Test Credentials

> **Security Note**: This file contains test account credentials for authorized engagement use only.
> Use only on systems listed in `target/scope.md`. Do not use these credentials on any other system.
> Delete or securely wipe this file after engagement completion.

---

## Test Accounts

| Role | Username / Email | Password | Notes |
|---|---|---|---|
| Anonymous | (no login) | — | Unauthenticated testing |
| User A | | | Primary low-priv test account |
| User B | | | Secondary low-priv (for IDOR testing) |
| Premium User | | | Paid tier features |
| Moderator | | | Content moderation role |
| Admin | | | Full admin access |

*(Fill in during pre-engagement with credentials provided by client)*

---

## API Keys / Tokens

| Purpose | Key / Token | Scope | Expiry |
|---|---|---|---|
| Test API key (user) | | read | |
| Test API key (admin) | | read/write | |
| OAuth client_id | | | |
| OAuth client_secret | | | |

---

## OAuth Test Accounts

| Provider | Email | Password | Notes |
|---|---|---|---|
| Google OAuth | | | Test Google-linked account |
| GitHub OAuth | | | Test GitHub-linked account |

---

## Special Access Notes

- **Admin account creation**: Was the admin account provided by client, or self-registered?
- **MFA setup**: Are MFA codes available for test accounts? (TOTP seed / backup codes)
- **Password reset tokens**: Are test accounts accessible via real email for reset flows?

---

## Credential Rotation

If credentials are found compromised or need rotation during the engagement:
- Contact: [client PoC name and contact]
- Escalation path: [engagement manager]
