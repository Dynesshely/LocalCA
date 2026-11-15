"""
Personal access token format and digest helpers.

Kept separate from the model and the middleware so both sides use exactly one
definition of the prefix and the digest. The raw token never reaches the
database; only :func:`hash_token` output does.
"""

import hashlib
import secrets

#: Prefix that makes a leaked LocalCA token recognizable to secret scanners.
TOKEN_PREFIX = 'lca_pat_'

#: Entropy in bytes; 32 bytes -> 43 url-safe characters after encoding.
TOKEN_BYTES = 32


def generate_token():
    """Create a new raw token. Returned to the caller exactly once."""
    return TOKEN_PREFIX + secrets.token_urlsafe(TOKEN_BYTES)


def hash_token(raw):
    """SHA-256 hex digest used for storage and lookup."""
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def display_prefix(raw):
    """The non-secret prefix shown in the token list."""
    return raw[:12]
