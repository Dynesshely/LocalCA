# Certificate operations

> Part of the [Local CA](../README.md) documentation. Issuing, downloading, renewing, importing and revoking certificates.

## Downloading certificates and keys

Every certificate in the hierarchy (and in the two creation pages) has a
**Download** menu offering the same set of formats, grouped by what they give
away. The list is served by `/api/meta/`, so the menu and the endpoints cannot
disagree.

| Format | What you get |
| --- | --- |
| Certificate (PEM) | The certificate on its own |
| Certificate (DER) | The same, binary, for Windows and Java tooling |
| Full chain (PEM) | The certificate, its intermediates and the root, in that order |
| Full chain (PKCS#7) | The whole chain in one `.p7b` |
| PKCS#12 bundle | Certificate and key in one password-protected `.p12` |
| Private key, encrypted | PKCS#8 `.key`, protected by a password you choose |
| Private key, unencrypted | PKCS#8 `.key`, no password — what nginx and apache need |
| Certificate + key bundle | A `.zip` holding `.crt`, `.key` and `chain.pem` |
| Full chain + key bundle | A `.zip` holding one `-fullchain.pem` (certificate, issuers, root last) and its unencrypted `.key` |

The first four are **public**: they are the certificate material a client needs
in order to trust this CA, so they need no session. The last five contain the
private key and require all of:

* an authenticated session, and that the certificate is **yours** — staff can
  revoke, delete and export the certificate of another account, but never its
  private key: the key is wrapped with *that* account's credential and there is no
  escrow, so the menu offers those formats as unavailable rather than letting the
  request fail;
* the **credential that wraps the key open**, so it can be decrypted at all — a
  locked one answers `409` with `vault_locked`, `credential_id` and
  `credential_name`, and the interface asks for that credential's password and
  then retries the exact request;
* for the protected formats, an export password of at least eight characters;
* for the unprotected ones, an explicit `confirm=true`. The interface puts that
  behind a checkbox, so a stray click cannot put a CA key on disk in the clear.

Every download is written to the audit log as `DOWNLOAD_PUBLIC_KEY`,
`DOWNLOAD_PRIVATE_KEY` or `DOWNLOAD_PKCS12`.

> Unprotected private keys exist because the alternative is worse: an operator
> who needs a bare `.key` for nginx will run `openssl pkcs12 -nodes` on their own
> machine, which leaves no audit trail and no ownership check at all. What the
> guards above buy is that it is never accidental, never someone else's key, and
> always recorded.

## Renewing a certificate

A certificate is what it was signed as, so LocalCA never edits one. **Renew** on a
leaf issues a *new* certificate and retires the old one:

* the **common name and the signing intermediate are inherited** — changing either
  is issuing a different certificate, which is what Create Leaf is for;
* the **SAN list is editable**, prefilled with the names the certificate already
  answers to, one per line or comma-separated;
* the **key pair is always regenerated**, because re-issuing around a key that may
  have leaked is the point of a renewal;
* the replacement's key is stored under **the same keystore credential** as the
  old one (an explicit `credential_id` overrides that), so a certificate filed
  under "Production" does not quietly move;
* the certificate being replaced is **revoked with reason `superseded`** and keeps
  a pointer to its replacement, so "which certificate is live for this name?" has
  one answer. It stays in the tree, marked *renewed*, and offers no second
  renewal — renew its replacement instead.

Renewal is available from the leaf table and from the leaf's card in the
hierarchy. `POST /api/certificates/leaf/<id>/renew/` takes `san` and
`validity_days`, and answers `409` when the signing CA's credential is locked
(with `credential_id`, so the interface can ask for the right password and retry).

## Importing certificates

LocalCA can ingest certificate material you already have: a CA with its private
key, a leaf certificate, or a whole chain. The page is **Import** in the top
navigation (`/import`).

Formats are recognised by **content, not by file extension**:

| Accepted | Notes |
| --- | --- |
| PEM | one or many objects per file; certificate and key may be in the same file or in separate files of one submission; `TRUSTED CERTIFICATE` labels are handled |
| Private keys | PKCS#8, PKCS#1, SEC1, and **encrypted** PKCS#8 or traditional OpenSSL (`Proc-Type: 4,ENCRYPTED`) — supply the password |
| DER | certificate, private key, PKCS#7 |
| PKCS#7 / P7B / P7C | DER and PEM. Certificates only, by construction |
| PKCS#12 / PFX | key plus certificate plus additional chain certificates; a single key entry |
| ZIP | a container for any of the above, which is what a bulk migration looks like |

Not supported: **JKS/JCEKS** Java keystores (convert first with
`keytool -importkeystore -destkeystore bundle.p12`), SSH keys and SSH
certificates, and PGP keys — none of those are X.509 material this application
could sign with or export.

### It is a two-step operation

1. **Analyze** uploads the files and returns a plan: every certificate found, the
   type it was recognised as, whether a matching private key came with it, where
   it would sit in the hierarchy, and whether it would be created, skipped or
   refused. **Nothing is written.**
2. **Import** re-uploads the same files to apply that plan.

Nothing is staged on the server between the two steps, so no uploaded key
material outlives a request.

### Two rules the importer follows

* **Private keys go through the keystore.** An imported key is wrapped exactly
  like a generated one, so an import that carries a key needs a credential open
  (you are prompted, the same way signing prompts you). There is no path that
  writes an uploaded key to the legacy cleartext column.
* **A certificate without a key is inventory.** It is listed, can be revoked and
  downloaded as PEM, but it cannot sign and cannot be exported as PKCS#12. The
  UI marks it `no private key`, and such a CA is left out of the signing menus
  rather than offered and then refused.

### What ends up where

* A **self-signed CA** becomes a root.
* An **intermediate** must be issued by a root that is in the upload or already
  stored; a **leaf** must be issued by an intermediate. A leaf issued directly by
  a root, or a self-signed end-entity certificate, cannot be represented in the
  root/intermediate/leaf model and is reported as such in the plan instead of
  being forced in.
* The same certificate twice (same SHA-256 fingerprint) is skipped when it is
  already stored. A certificate stored **without** a key, whose key is in the
  upload, gets the key **added**.
* A certificate whose serial number is already used by a *different* certificate
  is refused: serial numbers are unique across the application, so that one needs
  a human decision.
* Imported certificates belong to the account that imported them. A certificate
  may only be attached under a CA that account owns; staff may extend any CA.
* Every import is recorded in the audit log.

### Limits

Up to 8 files, 1 MiB per file, 5 MiB in total and 200 certificates/keys per
submission. ZIP archives are additionally capped by entry count, expanded size
and compression ratio.

### Treat an imported CA with the same care as a generated one

An imported private key is as sensitive as one LocalCA generated. If the CA you
import is already trusted by your clients, then anyone who can sign with it can
impersonate those services — and private keys leave this application under the
guards described in [Downloading certificates and keys](#downloading-certificates-and-keys).
