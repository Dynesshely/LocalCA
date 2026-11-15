# API and personal access tokens

LocalCA exposes the JSON API under `/api/`. The browser SPA uses Django's
session cookie plus CSRF; scripts, integrations and AI agents use a **personal
access token** (PAT) in an `Authorization: Bearer` header.

A PAT belongs to one account and has exactly that account's permissions. A staff
PAT can manage (read, revoke and delete) every certificate; an ordinary user's
PAT can only manage that user's certificates. Signing and private-key export
remain owner-only even for staff, because a key is wrapped with its owner's
keystore credential. Tokens do not have separate scopes, and they do not expire:
revoke one explicitly when it is no longer needed.

## Creating a token

Open **Access Tokens** in the sidebar (`/tokens`) and choose **New token**. The
full token is shown once; only its SHA-256 digest and a short display prefix are
stored. If it is lost, revoke it and create another.

Token management is intentionally session-only. A PAT cannot create, list or
revoke tokens (`403`), so a leaked token cannot mint a replacement.

The same operations are available to a signed-in session over HTTP:

| Method | Path | Body | Meaning |
| --- | --- | --- | --- |
| `GET` | `/api/tokens/` | — | List your tokens (revoked ones included) |
| `POST` | `/api/tokens/` | `{"name": "CI bot"}` | Create one; response contains the only copy |
| `POST` | `/api/tokens/<id>/revoke/` | — | Revoke it immediately |

Creation returns:

```json
{
  "ok": true,
  "token": "lca_pat_...",
  "access_token": {
    "id": 3,
    "name": "CI bot",
    "prefix": "lca_pat_ab12",
    "created_at": "2026-11-15T15:00:00+00:00",
    "last_used_at": null,
    "revoked_at": null,
    "revoked": false
  }
}
```

Every certificate action performed with the token is recorded in the audit log
under the token's owner.

## Using a token

```bash
export LOCALCA_URL="https://ca.example.net"
export LOCALCA_PAT="lca_pat_..."

curl -sS -H "Authorization: Bearer $LOCALCA_PAT" \
  "$LOCALCA_URL/api/certificates/" | jq
```

A token request is authenticated without a CSRF cookie. The response shape is the
same as for a signed-in session: `{"ok": true, ...}` on success,
`{"ok": false, "errors": ["..."]}` on failure, plus `field_errors` for
validation failures.

`GET /api/session/` is a cheap way to verify a token: it returns the owning user
without requiring another endpoint.

## Certificate endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/api/certificates/` | Full hierarchy the account may see |
| `GET` | `/api/certificates/mine/` | Only the account's certificates |
| `GET` | `/api/issuers/` | CAs this account may sign with |
| `POST` | `/api/certificates/create/root/` | Create a root CA |
| `POST` | `/api/certificates/create/intermediate/` | Create an intermediate CA |
| `POST` | `/api/certificates/create/leaf/` | Issue a leaf certificate |
| `POST` | `/api/certificates/leaf/<id>/renew/` | Re-issue a leaf with edited SANs |
| `POST` | `/api/certificates/<kind>/<id>/revoke/` | Revoke a root, intermediate or leaf |
| `POST` | `/api/certificates/<kind>/<id>/delete/` | Delete it and everything it signed |
| `GET` | `/api/download/<serial>/<format>/` | Download certificate or key material |
| `GET` | `/api/meta/` | Download formats, revocation reasons, validity bounds |

`kind` is one of `root`, `intermediate`, `leaf`.

### Create a root CA

```bash
curl -sS -X POST -H "Authorization: Bearer $LOCALCA_PAT" \
  -H "Content-Type: application/json" \
  -d '{"common_name": "Homelab Root CA", "validity_days": 3650}' \
  "$LOCALCA_URL/api/certificates/create/root/"
```

`credential_id` is optional; without it the new key is wrapped with the
account's default keystore credential. The credential must be **open** (unlocked
in the UI) before the request, otherwise the API answers `409` with
`vault_locked`, `credential_id` and `credential_name`.

### Create an intermediate CA

```bash
curl -sS -X POST -H "Authorization: Bearer $LOCALCA_PAT" \
  -H "Content-Type: application/json" \
  -d '{"common_name": "Services Intermediate CA", "validity_days": 1825, "root_id": 1}' \
  "$LOCALCA_URL/api/certificates/create/intermediate/"
```

### Issue a leaf certificate

```bash
curl -sS -X POST -H "Authorization: Bearer $LOCALCA_PAT" \
  -H "Content-Type: application/json" \
  -d '{"common_name": "grafana.home", "san": "grafana.home,192.168.x.x", "validity_days": 365, "intermediate_id": 2}' \
  "$LOCALCA_URL/api/certificates/create/leaf/"
```

`san` is a string; separate entries with commas or newlines. The common name is
added to the SAN list automatically.

### Renew a leaf

Renewal keeps the common name and issuer, regenerates the key pair, and revokes
the old certificate as `superseded` after pointing it at its replacement.

```bash
curl -sS -X POST -H "Authorization: Bearer $LOCALCA_PAT" \
  -H "Content-Type: application/json" \
  -d '{"san": "grafana.home,192.168.x.x,grafana.example.net", "validity_days": 365}' \
  "$LOCALCA_URL/api/certificates/leaf/3/renew/"
```

### Revoke and delete

```bash
# revoke
curl -sS -X POST -H "Authorization: Bearer $LOCALCA_PAT" \
  -H "Content-Type: application/json" \
  -d '{"type": "leaf", "id": 3, "reason": "key_compromise", "comment": "laptop lost"}' \
  "$LOCALCA_URL/api/certificates/leaf/3/revoke/"

# delete (irreversible; a CA also deletes everything it signed)
curl -sS -X POST -H "Authorization: Bearer $LOCALCA_PAT" \
  -d '{}' -H "Content-Type: application/json" \
  "$LOCALCA_URL/api/certificates/leaf/3/delete/"
```

Revocation reasons: `unspecified`, `key_compromise`, `ca_compromise`,
`affiliation_changed`, `superseded`, `cessation_of_operation`,
`certificate_hold`, `privilege_withdrawn`.

## Downloads

`GET /api/download/<serial>/<format>/` serves the formats listed by
`/api/meta/` (`download_formats`). Public formats need no session or token;
private-key formats require the owning account, an open keystore credential, and
(for unprotected keys) an explicit confirmation. A PAT may download its owner's
private-key formats, because it is the owner for API purposes.

## Errors

| Status | Meaning |
| --- | --- |
| `400` | Validation failure; see `errors` and `field_errors` |
| `401` | No session / invalid or revoked token |
| `403` | Authenticated but not allowed (ownership, staff-only, token management) |
| `404` | Certificate or token does not exist |
| `409` | Conflict: already revoked, already renewed, keystore locked |

A locked keystore is not a generic failure; the `409` body carries
`vault_locked`, `credential_id` and `credential_name` so the client can ask for
the right credential's password. Opening a credential is a UI action at
`/keystore`.

## Security

- Treat a PAT like a password. Store it in the client's secret store, never in a
  repository or a chat message, and revoke it when the client is retired.
- Use HTTPS. A token in plain HTTP is a token on the wire.
- Prefer one token per client so revocation is precise; the list shows the last
  time each token was used.
- A staff token inherits staff powers. Create staff tokens only for automation
  that actually needs cross-account access.

The MCP server built on this API is documented in [MCP.md](MCP.md).
