#!/usr/bin/env python3
"""LocalCA MCP server: certificate operations over the Model Context Protocol.

This is a dependency-free stdio server: JSON-RPC 2.0 messages, one per line, on
stdin and stdout. stdout carries protocol messages only; diagnostics go to
stderr. It authenticates to the LocalCA JSON API with a personal access token
(LOCALCA_PAT) and exposes the certificate hierarchy as MCP tools: list, get,
create (root, intermediate, leaf), renew a leaf, revoke and delete.

Configuration is read from the environment:

    LOCALCA_URL   Base URL of the LocalCA instance, default http://127.0.0.1:8000
    LOCALCA_PAT   Personal access token, required (lca_pat_...)

See docs/MCP.md for client configuration, the tool table and troubleshooting.
"""

import json
import os
import sys
import traceback
import urllib.error
import urllib.request

SERVER_NAME = "localca-mcp"
SERVER_VERSION = "0.1.0"

DEFAULT_URL = "http://127.0.0.1:8000"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")

CERTIFICATE_KINDS = ("root", "intermediate", "leaf")
REVOCATION_REASONS = (
    "unspecified",
    "key_compromise",
    "ca_compromise",
    "affiliation_changed",
    "superseded",
    "cessation_of_operation",
    "certificate_hold",
    "privilege_withdrawn",
)

REQUEST_TIMEOUT_SECONDS = 30

INSTRUCTIONS = (
    "LocalCA certificate management. Reads (list_certificates, get_certificate, "
    "list_issuers) answer from the LocalCA JSON API. Writes need a keystore "
    "credential that is already unlocked: open it in the LocalCA UI (Keystore "
    "page) before creating, renewing or importing keys, otherwise the API "
    "answers 409 vault_locked. Revoke and delete are recorded in the audit log; "
    "delete is irreversible."
)


def _log(message):
    """Write one diagnostic line to stderr (never stdout)."""
    print(f"[{SERVER_NAME}] {message}", file=sys.stderr, flush=True)


class ToolInputError(Exception):
    """A tool argument was missing or malformed."""


class ToolFailure(Exception):
    """The LocalCA API answered in a way the tool cannot use."""


class HttpError(Exception):
    """The LocalCA API answered with a non-2xx HTTP status."""

    def __init__(self, status, body, request_line):
        super().__init__(f"HTTP {status}")
        self.status = status
        self.body = body
        self.request_line = request_line


class InvalidParams(Exception):
    """The JSON-RPC request envelope itself is malformed."""


class MethodNotFound(Exception):
    """The JSON-RPC method is not implemented by this server."""

    def __init__(self, method):
        super().__init__(method)
        self.method = method


# ---------------------------------------------------------------------------
# Argument validation. Each helper raises ToolInputError, which tools/call
# turns into an isError result; the JSON-RPC envelope stays valid.
# ---------------------------------------------------------------------------

def _string_arg(args, name, *, required=True, allow_empty=False):
    """Return a string argument, or None when an optional one is absent."""
    if name not in args or args[name] is None:
        if required:
            raise ToolInputError(f'"{name}" is required and must be a string')
        return None
    value = args[name]
    if not isinstance(value, str):
        raise ToolInputError(f'"{name}" must be a string')
    if not allow_empty and not value.strip():
        raise ToolInputError(f'"{name}" must not be empty')
    return value


def _integer_arg(args, name, *, required=True, minimum=1):
    """Return an integer argument, or None when an optional one is absent."""
    if name not in args or args[name] is None:
        if required:
            raise ToolInputError(f'"{name}" is required and must be an integer')
        return None
    value = args[name]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolInputError(f'"{name}" must be an integer')
    if value < minimum:
        raise ToolInputError(f'"{name}" must be at least {minimum}')
    return value


def _boolean_arg(args, name):
    """Return a boolean argument, or None when it is absent."""
    if name not in args or args[name] is None:
        return None
    value = args[name]
    if not isinstance(value, bool):
        raise ToolInputError(f'"{name}" must be true or false')
    return value


def _string_list_arg(args, name, *, required=True):
    """Return a list of non-empty strings with surrounding whitespace removed."""
    if name not in args or args[name] is None:
        if required:
            raise ToolInputError(f'"{name}" is required and must be an array of strings')
        return None
    value = args[name]
    if not isinstance(value, list):
        raise ToolInputError(f'"{name}" must be an array of strings')
    entries = []
    for index, entry in enumerate(value):
        if not isinstance(entry, str):
            raise ToolInputError(f'"{name}[{index}]" must be a string')
        entry = entry.strip()
        if entry:
            entries.append(entry)
    return entries


def _kind_arg(args, name="kind"):
    """Return a certificate kind from the root/intermediate/leaf whitelist."""
    value = _string_arg(args, name)
    if value not in CERTIFICATE_KINDS:
        raise ToolInputError(
            f'"{name}" must be one of: {", ".join(CERTIFICATE_KINDS)}')
    return value


def _reason_arg(args):
    """Return an RFC 5280 revocation reason."""
    value = _string_arg(args, "reason")
    if value not in REVOCATION_REASONS:
        raise ToolInputError(
            f'"reason" must be one of: {", ".join(REVOCATION_REASONS)}')
    return value


def _add_credential(payload, args):
    """Copy an optional credential_id into an API request payload."""
    credential_id = _integer_arg(args, "credential_id", required=False)
    if credential_id is not None:
        payload["credential_id"] = credential_id


# ---------------------------------------------------------------------------
# Tool schemas. The table is what tools/list returns; the handlers below match
# it field for field.
# ---------------------------------------------------------------------------

_COMMON_NAME = {
    "type": "string",
    "minLength": 1,
    "maxLength": 255,
    "description": "Certificate common name (CN).",
}
_CREDENTIAL_ID = {
    "type": "integer",
    "minimum": 1,
    "description": (
        "Keystore credential that should wrap the new private key. Defaults to "
        "the account's default credential; it must already be unlocked in the UI."
    ),
}
_KIND = {
    "type": "string",
    "enum": list(CERTIFICATE_KINDS),
    "description": "Certificate kind: root, intermediate or leaf.",
}
_CERTIFICATE_ID = {
    "type": "integer",
    "minimum": 1,
    "description": "Numeric certificate id from list_certificates.",
}
_SAN = {
    "type": "array",
    "items": {"type": "string"},
    "description": (
        "Subject alternative names (DNS names and/or IP addresses). The API "
        "adds the common name automatically and de-duplicates the list."
    ),
}

TOOL_DEFINITIONS = (
    {
        "name": "list_certificates",
        "description": (
            "List the certificate hierarchy, flattened into one array. "
            "Each entry carries kind, id, name, "
            "serial_number, dates, owner, revocation and can_manage."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "kind": {
                    "type": "string",
                    "enum": list(CERTIFICATE_KINDS),
                    "description": "Only return certificates of this kind.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "get_certificate",
        "description": (
            "Fetch one certificate by kind and id, including its revocation "
            "state, owning account and whether the current user may manage it."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"kind": _KIND, "id": _CERTIFICATE_ID},
            "required": ["kind", "id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_issuers",
        "description": (
            "List the CA certificates this user may sign with: roots and "
            "intermediates that still have a stored private key. Imported CAs "
            "without a key are omitted because they cannot sign."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "create_root_ca",
        "description": (
            "Create a self-signed root CA. The generated private key is stored "
            "under credential_id (the account's default when omitted); that "
            "credential must already be unlocked in the LocalCA UI, otherwise "
            "the API answers 409 vault_locked."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "common_name": _COMMON_NAME,
                "validity_days": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 7300,
                    "description": "Lifetime in days (the server caps CA validity at 7300).",
                },
                "credential_id": _CREDENTIAL_ID,
            },
            "required": ["common_name", "validity_days"],
            "additionalProperties": False,
        },
    },
    {
        "name": "create_intermediate_ca",
        "description": (
            "Create an intermediate CA signed by an existing root. Both the "
            "root's key (to sign) and the target credential (to store the new "
            "key) must be unlocked in the LocalCA UI. Validity may not exceed "
            "the signing root's remaining lifetime."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "common_name": _COMMON_NAME,
                "validity_days": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 7300,
                    "description": "Lifetime in days (the server caps CA validity at 7300).",
                },
                "root_id": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Id of the root CA that should sign this intermediate.",
                },
                "credential_id": _CREDENTIAL_ID,
            },
            "required": ["common_name", "validity_days", "root_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "create_leaf_certificate",
        "description": (
            "Issue a leaf certificate signed by an intermediate CA. The "
            "intermediate's key and the target credential must be unlocked in "
            "the LocalCA UI. The private key is always generated fresh."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "common_name": _COMMON_NAME,
                "san": _SAN,
                "validity_days": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 825,
                    "description": "Lifetime in days (the server caps leaf validity at 825).",
                },
                "intermediate_id": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Id of the intermediate CA that should sign this leaf.",
                },
                "credential_id": _CREDENTIAL_ID,
            },
            "required": ["common_name", "san", "validity_days", "intermediate_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "renew_leaf_certificate",
        "description": (
            "Re-issue a leaf certificate with an edited SAN list. The common "
            "name and signing intermediate are inherited and the key pair is "
            "regenerated. The old certificate is revoked as superseded unless "
            "it was already revoked, and keeps a pointer to its replacement."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "integer",
                    "minimum": 1,
                    "description": "Id of the leaf certificate to renew.",
                },
                "san": _SAN,
                "validity_days": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 825,
                    "description": "Lifetime of the replacement in days.",
                },
                "credential_id": _CREDENTIAL_ID,
            },
            "required": ["id", "san", "validity_days"],
            "additionalProperties": False,
        },
    },
    {
        "name": "revoke_certificate",
        "description": (
            "Record a revocation with an RFC 5280 reason. Setting cascade to "
            "true also revokes every certificate signed by this CA. Revocation "
            "is recorded in the audit log; LocalCA does not publish a CRL, so "
            "already-installed certificates keep working until they expire."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "kind": _KIND,
                "id": _CERTIFICATE_ID,
                "reason": {
                    "type": "string",
                    "enum": list(REVOCATION_REASONS),
                    "description": "RFC 5280 CRLReason.",
                },
                "comment": {
                    "type": "string",
                    "maxLength": 500,
                    "description": "Optional free-form note stored with the revocation.",
                },
                "cascade": {
                    "type": "boolean",
                    "description": (
                        "Also revoke certificates signed by this CA (root and "
                        "intermediate only)."
                    ),
                },
            },
            "required": ["kind", "id", "reason"],
            "additionalProperties": False,
        },
    },
    {
        "name": "delete_certificate",
        "description": (
            "Permanently delete a certificate and everything it signed. "
            "Irreversible: the stored private key material is removed. The "
            "deletion is recorded in the audit log."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"kind": _KIND, "id": _CERTIFICATE_ID},
            "required": ["kind", "id"],
            "additionalProperties": False,
        },
    },
)

_TOOL_BY_NAME = {tool["name"]: tool for tool in TOOL_DEFINITIONS}


def _decode_body(raw):
    """Decode a response body, preferring JSON and falling back to text."""
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except ValueError:
        return text


def _flatten_tree(tree):
    """Turn GET /api/certificates/ tree entries into one flat certificate list."""
    certificates = []
    for root_entry in tree:
        if not isinstance(root_entry, dict):
            continue
        root = root_entry.get("certificate")
        if isinstance(root, dict):
            certificates.append(root)
        for intermediate_entry in root_entry.get("intermediates") or []:
            if not isinstance(intermediate_entry, dict):
                continue
            intermediate = intermediate_entry.get("certificate")
            if isinstance(intermediate, dict):
                certificates.append(intermediate)
            for leaf in intermediate_entry.get("leaves") or []:
                if isinstance(leaf, dict):
                    certificates.append(leaf)
    return certificates


def _hint_for(status, body):
    """Return an actionable hint for the errors an MCP client will hit most."""
    data = body if isinstance(body, dict) else {}
    if data.get("vault_locked"):
        credential_name = data.get("credential_name")
        target = (f'Keystore credential "{credential_name}"'
                  if credential_name else "The keystore credential this operation needs")
        return (
            f"{target} is locked. Unlock it in the LocalCA UI (Keystore page) "
            "and retry. 提示：请先在 LocalCA UI 的 Keystore 页面解锁该凭证后重试。"
        )
    if status == 401:
        return (
            "The personal access token was rejected. Check LOCALCA_PAT, and "
            "create a new token on the LocalCA Tokens page if it was revoked."
        )
    if status == 403:
        return (
            "This token's user may not perform that action. Owners manage their "
            "own certificates; staff users manage any certificate."
        )
    return None


def _tool_content(payload, is_error=False):
    """Build the content array an MCP tools/call result is made of."""
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


class Server:
    """One LocalCA MCP stdio server, bound to a URL and a PAT."""

    def __init__(self, base_url, pat):
        """Store the API endpoint and token, and bind the tool handlers."""
        self.base_url = base_url.rstrip("/")
        self.pat = pat
        self._handlers = {
            "list_certificates": self._list_certificates,
            "get_certificate": self._get_certificate,
            "list_issuers": self._list_issuers,
            "create_root_ca": self._create_root_ca,
            "create_intermediate_ca": self._create_intermediate_ca,
            "create_leaf_certificate": self._create_leaf_certificate,
            "renew_leaf_certificate": self._renew_leaf_certificate,
            "revoke_certificate": self._revoke_certificate,
            "delete_certificate": self._delete_certificate,
        }

    # -- transport ---------------------------------------------------------

    def _request(self, method, path, payload=None):
        """Call the LocalCA JSON API and return the decoded response body.

        Non-2xx answers raise HttpError with the status and the body intact so
        tools/call can show both to the client.
        """
        url = self.base_url + path
        request_line = f"{method} {path}"
        body = None
        headers = {
            "Authorization": f"Bearer {self.pat}",
            "Accept": "application/json",
            "User-Agent": f"{SERVER_NAME}/{SERVER_VERSION}",
        }
        if payload is not None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=body, headers=headers,
                                         method=method)
        try:
            with urllib.request.urlopen(
                    request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                return _decode_body(response.read())
        except urllib.error.HTTPError as exc:
            raise HttpError(exc.code, _decode_body(exc.read()),
                            request_line) from exc
        except urllib.error.URLError as exc:
            raise ToolFailure(
                f"Could not reach LocalCA at {self.base_url}: {exc.reason}") from exc
        except OSError as exc:
            raise ToolFailure(
                f"Could not reach LocalCA at {self.base_url}: {exc}") from exc

    # -- reads -------------------------------------------------------------

    def _certificate_tree(self):
        """Fetch the hierarchy and return its (unfiltered) tree array."""
        body = self._request("GET", "/api/certificates/")
        if not isinstance(body, dict) or not isinstance(body.get("tree"), list):
            raise ToolFailure(
                "GET /api/certificates/ did not return a certificate tree: "
                + json.dumps(body, ensure_ascii=False)[:500])
        return body["tree"]

    def _list_certificates(self, args):
        """Tool: list the visible certificate hierarchy."""
        kind = _kind_arg(args) if "kind" in args and args["kind"] is not None else None
        certificates = _flatten_tree(self._certificate_tree())
        if kind is not None:
            certificates = [entry for entry in certificates
                            if entry.get("kind") == kind]
        result = {"ok": True, "count": len(certificates),
                  "certificates": certificates}
        if kind is not None:
            result["kind"] = kind
        return result

    def _get_certificate(self, args):
        """Tool: fetch one certificate by kind and id."""
        kind = _kind_arg(args)
        cert_id = _integer_arg(args, "id")
        for entry in _flatten_tree(self._certificate_tree()):
            if entry.get("kind") == kind and entry.get("id") == cert_id:
                return {"ok": True, "certificate": entry}
        raise ToolFailure(
            f"No {kind} certificate with id {cert_id} exists.")

    def _list_issuers(self, args):
        """Tool: list the CAs the token's user can sign with."""
        del args
        return self._request("GET", "/api/issuers/")

    # -- writes ------------------------------------------------------------

    def _create_root_ca(self, args):
        """Tool: create a self-signed root CA."""
        payload = {
            "common_name": _string_arg(args, "common_name").strip(),
            "validity_days": _integer_arg(args, "validity_days"),
        }
        _add_credential(payload, args)
        return self._request("POST", "/api/certificates/create/root/", payload)

    def _create_intermediate_ca(self, args):
        """Tool: create an intermediate CA signed by a root."""
        payload = {
            "common_name": _string_arg(args, "common_name").strip(),
            "validity_days": _integer_arg(args, "validity_days"),
            "root_id": _integer_arg(args, "root_id"),
        }
        _add_credential(payload, args)
        return self._request("POST", "/api/certificates/create/intermediate/",
                             payload)

    def _create_leaf_certificate(self, args):
        """Tool: issue a leaf certificate from an intermediate."""
        payload = {
            "common_name": _string_arg(args, "common_name").strip(),
            "san": "\n".join(_string_list_arg(args, "san")),
            "validity_days": _integer_arg(args, "validity_days"),
            "intermediate_id": _integer_arg(args, "intermediate_id"),
        }
        _add_credential(payload, args)
        return self._request("POST", "/api/certificates/create/leaf/", payload)

    def _renew_leaf_certificate(self, args):
        """Tool: re-issue a leaf with an edited SAN list."""
        cert_id = _integer_arg(args, "id")
        payload = {
            "san": "\n".join(_string_list_arg(args, "san")),
            "validity_days": _integer_arg(args, "validity_days"),
        }
        _add_credential(payload, args)
        return self._request(
            "POST", f"/api/certificates/leaf/{cert_id}/renew/", payload)

    def _revoke_certificate(self, args):
        """Tool: revoke a certificate, optionally cascading to its children."""
        kind = _kind_arg(args)
        cert_id = _integer_arg(args, "id")
        payload = {
            "type": kind,
            "id": cert_id,
            "reason": _reason_arg(args),
        }
        comment = _string_arg(args, "comment", required=False, allow_empty=True)
        if comment is not None:
            payload["comment"] = comment
        cascade = _boolean_arg(args, "cascade")
        if cascade is not None:
            payload["cascade"] = cascade
        return self._request(
            "POST", f"/api/certificates/{kind}/{cert_id}/revoke/", payload)

    def _delete_certificate(self, args):
        """Tool: delete a certificate and everything it signed."""
        kind = _kind_arg(args)
        cert_id = _integer_arg(args, "id")
        return self._request(
            "POST", f"/api/certificates/{kind}/{cert_id}/delete/", {})

    # -- MCP methods -------------------------------------------------------

    def _initialize(self, params):
        """Handle initialize: negotiate a protocol version and advertise tools."""
        requested = params.get("protocolVersion")
        if requested is not None and not isinstance(requested, str):
            raise InvalidParams('"protocolVersion" must be a string')
        version = (requested if requested in SUPPORTED_PROTOCOL_VERSIONS
                   else DEFAULT_PROTOCOL_VERSION)
        client = params.get("clientInfo")
        if isinstance(client, dict):
            _log(f"initialize from {client.get('name', 'unknown client')} "
                 f"(requested protocol {requested!r})")
        else:
            _log(f"initialize (requested protocol {requested!r})")
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            "instructions": INSTRUCTIONS,
        }

    def _call_tool(self, params):
        """Validate a tools/call envelope and run one tool."""
        name = params.get("name")
        if not isinstance(name, str) or not name:
            raise InvalidParams('tools/call requires a string "name"')
        arguments = params.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise InvalidParams('tools/call "arguments" must be an object')
        handler = self._handlers.get(name)
        if handler is None:
            raise InvalidParams(f"Unknown tool: {name}")
        allowed = set(_TOOL_BY_NAME[name]["inputSchema"]["properties"])
        unknown = sorted(set(arguments) - allowed)
        if unknown:
            return _tool_content(
                {"ok": False,
                 "errors": [f"Unknown argument(s) for {name}: "
                            + ", ".join(unknown)]},
                is_error=True)
        try:
            payload = handler(arguments)
        except (ToolInputError, ToolFailure) as exc:
            return _tool_content(
                {"ok": False, "errors": [str(exc)]}, is_error=True)
        except HttpError as exc:
            payload = {
                "ok": False,
                "error": f"HTTP {exc.status}",
                "status": exc.status,
                "body": exc.body,
                "request": exc.request_line,
            }
            hint = _hint_for(exc.status, exc.body)
            if hint is not None:
                payload["hint"] = hint
            return _tool_content(payload, is_error=True)
        except ValueError as exc:
            return _tool_content(
                {"ok": False, "errors": [f"Invalid JSON value: {exc}"]},
                is_error=True)
        return _tool_content(payload)

    @staticmethod
    def _send(message):
        """Write one protocol message to stdout."""
        sys.stdout.write(json.dumps(message, ensure_ascii=False,
                                    separators=(",", ":")) + "\n")
        sys.stdout.flush()

    def _send_result(self, msg_id, result):
        """Answer a request successfully."""
        self._send({"jsonrpc": "2.0", "id": msg_id, "result": result})

    def _send_error(self, msg_id, code, message):
        """Answer a request with a JSON-RPC error."""
        self._send({"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": code, "message": message}})

    def _invalid_envelope(self, has_id, msg_id, code, message):
        """Answer a malformed request, but never a notification."""
        if has_id:
            self._send_error(msg_id, code, message)

    def _validated_request(self, message):
        """Return (has_id, id, method, params), or None after replying."""
        if not isinstance(message, dict):
            self._send_error(None, -32600, "Invalid Request")
            return None
        has_id = "id" in message
        msg_id = message.get("id")
        if message.get("jsonrpc") != "2.0":
            self._invalid_envelope(has_id, msg_id, -32600,
                                   'Invalid Request: "jsonrpc" must be "2.0"')
            return None
        method = message.get("method")
        if not isinstance(method, str):
            self._invalid_envelope(has_id, msg_id, -32600,
                                   'Invalid Request: "method" must be a string')
            return None
        params = message.get("params", {})
        if params is None:
            params = {}
        if not isinstance(params, dict):
            self._invalid_envelope(has_id, msg_id, -32602,
                                   'Invalid params: "params" must be an object')
            return None
        return has_id, msg_id, method, params

    def handle_message(self, message):
        """Validate and dispatch one decoded JSON-RPC message."""
        request = self._validated_request(message)
        if request is None:
            return
        has_id, msg_id, method, params = request
        if method.startswith("notifications/"):
            # notifications/initialized, notifications/cancelled, ... are
            # fire-and-forget and must never be answered.
            return
        if not has_id:
            _log(f"ignoring request without an id: {method}")
            return
        try:
            result = self._execute(method, params)
        except MethodNotFound as exc:
            self._send_error(msg_id, -32601, f"Method not found: {exc.method}")
        except InvalidParams as exc:
            self._send_error(msg_id, -32602, f"Invalid params: {exc}")
        except Exception:  # pylint: disable=broad-exception-caught
            _log("unhandled error while serving a request:\n"
                 + traceback.format_exc())
            self._send_error(msg_id, -32603, "Internal error")
        else:
            self._send_result(msg_id, result)

    def _execute(self, method, params):
        """Return the result for one JSON-RPC method, or raise."""
        if method == "initialize":
            return self._initialize(params)
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": list(TOOL_DEFINITIONS)}
        if method == "tools/call":
            return self._call_tool(params)
        raise MethodNotFound(method)

    def serve(self):
        """Read newline-delimited JSON-RPC from stdin until EOF."""
        _log(f"serving LocalCA at {self.base_url} over stdio")
        for raw_line in sys.stdin.buffer:
            try:
                line = raw_line.decode("utf-8").strip()
            except UnicodeDecodeError:
                self._send_error(None, -32700, "Parse error")
                continue
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError:
                self._send_error(None, -32700, "Parse error")
                continue
            self.handle_message(message)
        _log("stdin closed, exiting")


def _load_config():
    """Read LOCALCA_URL and LOCALCA_PAT, or return None with a stderr note."""
    base_url = (os.environ.get("LOCALCA_URL") or DEFAULT_URL).strip()
    base_url = (base_url or DEFAULT_URL).rstrip("/")
    pat = (os.environ.get("LOCALCA_PAT") or "").strip()
    if not pat:
        _log("LOCALCA_PAT is required: create a token on the LocalCA Tokens "
             "page and pass it in the environment")
        return None
    return base_url, pat


def main():
    """Run the stdio server; returns the process exit code."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    config = _load_config()
    if config is None:
        return 2
    base_url, pat = config
    try:
        Server(base_url, pat).serve()
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
