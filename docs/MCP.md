# MCP server

> Part of the [Local CA](../README.md) documentation. Driving LocalCA from an MCP client such as Claude Desktop or Claude Code with a personal access token.

LocalCA ships a Model Context Protocol (MCP) server at `scripts/localca_mcp.py`. It lets an MCP client list the certificate hierarchy and create, renew, revoke and delete certificates through the same JSON API the interface uses.

The server is **pure Python standard library**: it needs no `pip install`, no Node runtime and no build step. It starts no listener; the MCP client starts it as a child process and speaks newline-delimited JSON-RPC 2.0 over stdin/stdout. Every call goes to LocalCA over HTTP with `Authorization: Bearer <PAT>`, so the API's own validation and permission rules apply unchanged.

## Create a personal access token

1. Sign in to LocalCA as the account the server should act as.
2. Open **Administration → Access Tokens** (`/tokens`).
3. **Create** a token with a name that says where it is used (`Claude Desktop`, `CI runner`, ...).
4. Copy the `lca_pat_...` value immediately. It is shown **once**; LocalCA stores only its SHA-256 digest and a short display prefix.
5. Revoke it from the same page when it is no longer needed.

A PAT has exactly the permissions of its owner: there is no separate scope model, and a token created by a staff user can revoke or delete any certificate. Signing still requires the CA to belong to the token's user (see [Permissions and security model](#permissions-and-security-model)). Use one token per client, and prefer a dedicated account where a narrower blast radius matters.

Token management itself is **session-only**. A PAT cannot list, create or revoke tokens: `GET/POST /api/tokens/` and `POST /api/tokens/<id>/revoke/` answer **403** when called with a bearer token. This is deliberate — a leaked token must not be able to extend its own lifetime or mint a replacement.

## Configure an MCP client

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `LOCALCA_URL` | no | `http://127.0.0.1:8000` | Base URL of the LocalCA instance. A path prefix works: `https://host/localca` calls `https://host/localca/api/...`. |
| `LOCALCA_PAT` | **yes** | — | The `lca_pat_...` value. The server exits with status 2 when it is missing. |

Put the token in the client's **environment**, not in `args`: command-line arguments are visible to other users in the process list.

### Claude Desktop

The config file is `claude_desktop_config.json`:

* macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
* Windows: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "localca": {
      "command": "python3",
      "args": ["/path/to/LocalCA/scripts/localca_mcp.py"],
      "env": {
        "LOCALCA_URL": "https://localca.example.com",
        "LOCALCA_PAT": "lca_pat_replace_me"
      }
    }
  }
}
```

On Windows use `"command": "python"` (or the full path to `python.exe`) and a Windows path to the script. Restart the client after editing the file: Claude Desktop starts its MCP servers at launch.

### Claude Code

```bash
claude mcp add localca --env LOCALCA_URL=https://localca.example.com --env LOCALCA_PAT=lca_pat_replace_me -- python3 /path/to/LocalCA/scripts/localca_mcp.py
```

### Any other MCP client

The server is a normal stdio MCP server with no arguments:

| Setting | Value |
| --- | --- |
| `command` | `python3` (or the interpreter to use) |
| `args` | absolute path to `scripts/localca_mcp.py` |
| `env` | `LOCALCA_URL`, `LOCALCA_PAT` |

Supported protocol versions are `2024-11-05` (the default), `2025-03-26` and `2025-06-18`. On `initialize` the server echoes the client's requested version when it is supported, and otherwise answers `2024-11-05`.

## Tools

Every tool answers through `tools/call` with `content: [{"type": "text", "text": "<pretty JSON>"}]`. `isError` is set for HTTP failures and invalid arguments. The text is the LocalCA API's response body (pretty-printed), so the API's `ok`/`errors`/`field_errors` shape is what a client sees.

| Tool | Inputs | LocalCA endpoint |
| --- | --- | --- |
| `list_certificates` | `kind`? (`root`, `intermediate`, `leaf`) | `GET /api/certificates/`, flattened |
| `get_certificate` | `kind`, `id` | `GET /api/certificates/`, lookup by kind and id |
| `list_issuers` | — | `GET /api/issuers/` |
| `create_root_ca` | `common_name`, `validity_days`, `credential_id`? | `POST /api/certificates/create/root/` |
| `create_intermediate_ca` | `common_name`, `validity_days`, `root_id`, `credential_id`? | `POST /api/certificates/create/intermediate/` |
| `create_leaf_certificate` | `common_name`, `san` (array), `validity_days`, `intermediate_id`, `credential_id`? | `POST /api/certificates/create/leaf/` |
| `renew_leaf_certificate` | `id`, `san` (array), `validity_days`, `credential_id`? | `POST /api/certificates/leaf/<id>/renew/` |
| `revoke_certificate` | `kind`, `id`, `reason`, `comment`?, `cascade`? | `POST /api/certificates/<kind>/<id>/revoke/` |
| `delete_certificate` | `kind`, `id` | `POST /api/certificates/<kind>/<id>/delete/` |

Notes:

* `validity_days` is bounded by the API: 1–7300 for roots and intermediates, 1–825 for leaves and renewals, and a subordinate certificate may not outlive its issuer.
* `san` is an array of DNS names and/or IP addresses. The server joins it with newlines for the API, which accepts commas and newlines, de-duplicates entries and prepends the common name. A leaf can therefore be issued with only its common name by passing an empty array.
* `reason` is one of `unspecified`, `key_compromise`, `ca_compromise`, `affiliation_changed`, `superseded`, `cessation_of_operation`, `certificate_hold` or `privilege_withdrawn`.
* `revoke_certificate` sends `type` and `id` in the body as well as in the URL, because the API checks that the two agree; `cascade` also revokes every certificate signed by the CA.
* `list_certificates` returns entries with `kind`, `id`, `name`, `serial_number`, dates, owner, `can_manage`, key state and revocation. Leaves also carry `sans`, `signed_by` and `renewed_by`. Private key material is never returned.
* Arguments are validated before any HTTP request, so a missing or mistyped argument is reported without touching the API.

A successful `create_leaf_certificate` returns the API's 201 body:

```json
{
  "ok": true,
  "certificate": {
    "kind": "leaf",
    "id": 12,
    "name": "wiki.example",
    "serial_number": "5a:2f:...",
    "valid_until": "2027-02-01T12:00:00+00:00"
  }
}
```

An HTTP failure is reported as an `isError` result that keeps the status and the body:

```json
{
  "ok": false,
  "error": "HTTP 409",
  "status": 409,
  "body": {
    "ok": false,
    "errors": ["The keystore credential \"Production\" is locked. ..."],
    "vault_locked": true,
    "credential_id": 3,
    "credential_name": "Production"
  },
  "request": "POST /api/certificates/leaf/12/renew/",
  "hint": "Keystore credential \"Production\" is locked. Unlock it in the LocalCA UI (Keystore page) and retry. ..."
}
```

## Permissions and security model

* **The token is the account.** A PAT resolves to its owner and the request runs as that user; there are no scopes, no read-only tokens and no service accounts. A staff token can revoke or delete any certificate. Use separate LocalCA accounts if you need separate authority.
* **Managing versus signing.** Owners may manage their own certificates and staff users may manage any certificate, which is what `can_manage` in `list_certificates`/`get_certificate` reports. Signing is narrower: `list_issuers` and the creation forms only accept **the user's own** CAs that still have a private key, so even a staff token cannot issue under another account's CA.
* **Metadata, not keys.** Certificate listing returns names, serials, validity, revocation state and key *state* (which credential wraps a key, and whether it is open). No tool returns private key material or a download.
* **CSRF.** Bearer requests under `/api/` bypass CSRF checks; browser requests authenticated by session keep the normal CSRF behaviour. Token management stays session-only, so a leaked token cannot rewrite its own lifecycle.
* **Token lifecycle.** `last_used_at` is updated on every authenticated request, which is how the Tokens page shows stale tokens. Revoked tokens are rejected immediately with **401** and `WWW-Authenticate: Bearer`; deactivating the owner has the same effect.
* **Audit trail.** Create, renew, revoke and delete operations are recorded in the audit log with the token's owner as the actor, exactly as when the UI performs them. The token itself is not recorded.
* **Handle it like a password.** Keep the PAT in the client's environment or a restricted-permission env file, never in a repository, shell history or a screenshot. Revoke it at `/tokens` if it leaks; revocation is immediate and the token is kept in the list as revoked for the audit trail.
* **Destructive operations are exposed deliberately.** `delete_certificate` is irreversible and deletes everything the certificate signed; `revoke_certificate` records the revocation (LocalCA does not serve a CRL or OCSP responder, so already-installed certificates keep working until they expire).

## Keystore lock

Creating or renewing a certificate stores a new private key, and issuing an intermediate or leaf also consumes the issuer's private key. The API therefore requires the relevant keystore credentials to be **open**:

* the **target credential** (the one that will wrap the new key), which is `credential_id` when given, otherwise the account's default credential; and
* for an intermediate, leaf or renewal, the **issuer's credential** (the root or intermediate that signs).

The MCP server cannot unlock a credential: it has no unlock tool and never asks for the vault password. **Open the credential on the Keystore page (`/keystore`) first**, then call the tool. Opening it once is enough for every client talking to that LocalCA process; the credential stays open for 15 minutes of inactivity by default (`LOCALCA_VAULT_IDLE_TIMEOUT` changes that).

When a credential is locked the API answers **409** with `vault_locked: true`, `credential_id` and `credential_name`. The server adds a `hint` that names the credential and points at the Keystore page. An account with no credential yet gets the same 409 with `credential_id: null`; create a credential in the UI first.

## Example conversation

> **You:** List my leaf certificates, then renew `wiki.example` for 90 days with SANs `wiki.example` and `www.wiki.example`.

The client would:

1. call `list_certificates` with `{"kind": "leaf"}` to find the certificate id (and `can_manage`);
2. call `renew_leaf_certificate` with `{"id": 12, "san": ["wiki.example", "www.wiki.example"], "validity_days": 90}`.

The renewal issues a new certificate, inherits the common name and signing intermediate, regenerates the key pair, and revokes the old one as `superseded` with a pointer to its replacement — unless the old one was already revoked, in which case that revocation is preserved. The old certificate is not deleted; use `delete_certificate` only when the audit value of the row is no longer wanted.

Underneath, the client's second call is one JSON-RPC line:

```json
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"renew_leaf_certificate","arguments":{"id":12,"san":["wiki.example","www.wiki.example"],"validity_days":90}}}
```

A client that wants a full trace can send the same line on stdin to the server directly (see the manual test below).

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| The client shows no tools, or the server exits at once | Wrong script path, wrong interpreter, or `LOCALCA_PAT` not passed | MCP clients do not inherit your shell environment: put both variables in the client config. Run the manual test below to see the server's stderr. |
| `LOCALCA_PAT is required ...` on stderr, exit status 2 | The environment variable is missing or empty | Add it to `env` in the client config, then restart the client. |
| **401** `Invalid or revoked personal access token.` | Typo, revoked token, or deactivated owner | Create a new token at `/tokens`, update `LOCALCA_PAT`, restart the client. |
| **403** `Access tokens can only be managed from a signed-in session.` | A PAT was used against `/api/tokens/` | Manage tokens in the UI or with a session; the MCP server has no token tools. |
| **403** `You do not have permission ...` / `You can only renew a certificate you own.` | The token's user is not the owner and is not staff | Use the owner's token or a staff token; check `can_manage` first. |
| **404** `That certificate does not exist.` | Wrong kind or id | `list_certificates` or `get_certificate` first; kind and id must both match. |
| **400** with `errors`/`field_errors` | Server-side validation: duplicate name, validity longer than the issuer, no SAN, unknown issuer id, ... | Read the message; it is the same text the UI would show. |
| **409** with `vault_locked: true` | The target or issuer credential is locked | Open it on the Keystore page, then retry. See [Keystore and key operations](KEYSTORE.md). |
| **409** `already revoked` / `already renewed` / `already in use` | State conflict | `get_certificate` to confirm the current state; renew the replacement instead, or choose another name. |
| **409** `No keystore credential exists yet` | The account has no credential | Create one on the Keystore page, then retry. |
| `Could not reach LocalCA at ...` | Wrong `LOCALCA_URL`, server down, or a reverse-proxy path prefix omitted | Check the URL includes any prefix, and test it with `curl` (below). Requests time out after 30 seconds. |
| TLS certificate verification fails | The instance's certificate is issued by an internal CA the host does not trust | Add that CA to the host trust store. The server has no insecure mode. |
| Client reports a parse error or disconnects | Something wrote to stdout | Only the server may write protocol lines to stdout; it logs to stderr. Run it directly and keep its stdout on the protocol. |

Check connectivity and the token with the API directly — a valid token returns your user object:

```bash
curl -sS -H "Authorization: Bearer $LOCALCA_PAT" "$LOCALCA_URL/api/session/"
```

### 401, 403 and 409 in detail

* **401** comes from the PAT middleware before any view runs: the token is unknown, revoked, or its owner is inactive. The response carries `WWW-Authenticate: Bearer`. It is not a vault problem and no UI unlock will fix it.
* **403** with the token-management message means the request hit `/api/tokens/` with a PAT; that endpoint is session-only on purpose. Any other 403 is a certificate permission decision (owner or staff).
* **409** is a state conflict. `vault_locked: true` means "unlock a credential first"; the other 409s mean the certificate is already revoked, already has a replacement, or the name is taken.

## Manual protocol test

The server needs `LOCALCA_PAT` even when you only exercise the protocol, but no real token or running LocalCA instance is needed for `initialize` and `tools/list`:

```bash
LOCALCA_PAT=lca_pat_self_test python3 scripts/localca_mcp.py <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"manual","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
EOF
```

Expect exactly two stdout lines: one `initialize` result and one `tools/list` result. The notification produces no response, and the process exits 0 at EOF. To check that every line is valid JSON-RPC and that nothing else polluted stdout:

```bash
LOCALCA_PAT=lca_pat_self_test python3 scripts/localca_mcp.py <<'EOF' | python3 -c 'import json, sys; [json.loads(line) for line in sys.stdin if line.strip()]'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"manual","version":"0"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
EOF
```

Protocol details:

* One JSON-RPC 2.0 object per line; no framing, no embedded newlines, no pretty printing.
* Methods: `initialize`, `notifications/initialized` (and other `notifications/*`, ignored), `ping`, `tools/list`, `tools/call`.
* Notifications are never answered. Unknown methods get `-32601`; a malformed `tools/call` envelope or an unknown tool gets `-32602`; malformed JSON gets `-32700`; an unexpected server failure gets `-32603`. Invalid arguments to a known tool come back as an `isError` result, not as a JSON-RPC error.
* `initialize` advertises `capabilities.tools` and returns `serverInfo` (`localca-mcp`); `instructions` repeats the keystore-unlock requirement so the model sees it up front.
* stdout carries protocol messages only. All logs and tracebacks go to stderr.

## Limitations

* Tools only: no MCP resources, prompts, sampling, progress notifications or subscriptions.
* No certificate import or download tools yet; use the UI or the JSON API for those.
* No CRL or OCSP: revocation is recorded in LocalCA, not published to relying parties.
* One base URL and one token per process. Run another instance of the server for another account or instance.
* Certificate ids are numeric and instance-local; never assume they match another LocalCA deployment.

## See also

* [API and personal access tokens](API.md) — the HTTP endpoints, token format and request/response shapes behind these tools.
* [Certificate operations](CERTIFICATES.md) — issuing, renewing, importing, revoking and downloading.
* [Keystore and key operations](KEYSTORE.md) — credentials, the vault idle timeout and what a locked credential means.
* [Architecture and development](DEVELOPMENT.md) — the API modules and the development setup.
