"""Pure helpers that recognise and normalise personal identifiers.

Identifiers are represented as typed tokens such as ``email:a@b.com`` or
``user:user_12`` so that matching is exact and decoys such as
``g.silva76.jr@gmail.com`` never match ``g.silva76@gmail.com``.
"""

from __future__ import annotations

import hashlib
import re

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
USER_REF_RE = re.compile(r"\buser_\d+\b")
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b")
# International phone numbers as they appear in the dataset: "+82 10 2466 4678", "+1 (202) 555-0103".
PHONE_RE = re.compile(r"\+\d[\d\s().\-]{6,}\d")

DIRECT_KINDS = frozenset({"email", "phone", "hash", "name"})


def email_token(value: str) -> str:
    return "email:" + value.strip().lower()


def phone_token(value: str) -> str:
    return "phone:" + re.sub(r"\D", "", value)


def hash_token(value: str) -> str:
    return "hash:" + value.strip().lower()


def user_token(value: str) -> str:
    return "user:" + value.strip().lower()


def name_token(value: str) -> str:
    return "name:" + " ".join(value.strip().lower().split())


def email_hash(email: str) -> str:
    """The dataset's email_hash is sha256 of the lower-cased email."""
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def tokens_from_text(text: str) -> set[str]:
    """Extract every recognisable identifier token from free text."""
    tokens: set[str] = set()
    if not text:
        return tokens
    for m in EMAIL_RE.findall(text):
        tokens.add(email_token(m))
    for m in USER_REF_RE.findall(text.lower()):
        tokens.add(user_token(m))
    for m in HASH_RE.findall(text.lower()):
        tokens.add(hash_token(m))
    for m in PHONE_RE.findall(text):
        digits = re.sub(r"\D", "", m)
        if 8 <= len(digits) <= 15:
            tokens.add("phone:" + digits)
    return tokens


def token_kind(token: str) -> str:
    return token.split(":", 1)[0]


def direct_kinds(tokens: set[str] | frozenset[str]) -> set[str]:
    """Kinds of *direct* identifiers present (a stable user_id reference is not direct)."""
    return {token_kind(t) for t in tokens if token_kind(t) in DIRECT_KINDS}
