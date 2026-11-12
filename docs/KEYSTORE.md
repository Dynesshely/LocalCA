# Keystore and key operations

> Part of the [Local CA](../README.md) documentation. The [README](../README.md#security-model) has the summary; this page is the operational detail.

## Private keys are encrypted at rest

Certificate private keys are not stored in cleartext. Each is wrapped with a
**keystore credential**: a name, a password, and the root key that password
unwraps. An account may hold several — one for production, one for a lab — and
every private key records the credential that wraps it, so a password that leaks
or is forgotten costs you that credential rather than the whole account.

The [Keystore](../README.md#screenshots) page is where this is managed, and it is the honest
inventory: each key with its state (encrypted and open, encrypted and locked,
cleartext, ownerless, no key at all) and the credential's name next to it.

* On your first action that needs a key — signing, not merely exporting a
  certificate that predates the keystore — LocalCA asks you to **create a
  credential**. It is not the same as your login password, though nothing stops
  you using the same value. Keys of yours that are still cleartext are
  **encrypted at that moment**, so an account never sits half-protected because
  somebody forgot to run a command.
* Each credential is opened on its own, with its own password, and stays open in
  the server's memory for 15 minutes of inactivity
  (`LOCALCA_VAULT_IDLE_TIMEOUT` to change it) before locking again. Opening one
  does not open another, and either can be locked from the page — one at a time,
  or all at once.
* **There is no recovery.** If a credential's password is lost, every private key
  under *that credential* becomes permanently unreadable, including CA keys. No
  administrator can reset it — which is also why a key that must stay reachable
  after a lost password should live under a credential of its own. A credential
  with keys still pointing at it cannot be deleted; move them somewhere else
  first.
* New keys go to the credential marked **default**, unless a request names another
  one. A certificate's key can be moved between credentials from the keystore
  page: it is decrypted with the one that holds it and re-encrypted with the
  target, so nothing is copied.
* Keys belonging to a certificate with no owner remain cleartext: there is no
  account whose credential could wrap them, so `python manage.py vault_status`
  lists them as `orphaned`. Assign an owner and run
  `python manage.py rewrap_keys --username <user>` to encrypt the rest.
* Private keys leave the server only through the Download menu's guarded formats:
  two password-protected ones, one where you choose the passphrase, and one that
  must be explicitly confirmed. See
  [Downloading certificates and keys](CERTIFICATES.md#downloading-certificates-and-keys).

## Revoking a certificate

Certificates can be revoked from the UI (leaf, intermediate and root). The
revocation is recorded here with an RFC 5280 reason code and an audit entry, so
"revoked" in this app means "recorded and no longer offered for download" — it
is **not** published to clients. LocalCA does not yet serve a CRL or an OCSP
responder, so a certificate that was already installed keeps working until it
expires or you remove it from the trusting system. The confirmation dialog says
this explicitly before you revoke.

## Deleting certificates

Deleting removes the private key material from the database and cannot be
undone. Deleting a root or intermediate also deletes everything it signed; the
UI warns with the exact count first. Owners may manage their own certificates,
and staff users may manage any certificate.
