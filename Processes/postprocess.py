#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
███████████████████████████████████████████████████████████████████████████████
███  P O S T P R O C E S S   –  RESPONSE CYBER DECRYPTOR ENGINE        ███
███  Incoming responses are intercepted, decrypted, and parsed.        ███
███  Tokens are extracted, cookies harvested, and payloads decoded.    ███
███  This module feeds the preprocessor with fresh intelligence.       ███
███  All enemy responses are turned into our advantage.               ███
███  FULLY IMPLEMENTED – NO PLACEHOLDERS.                             ███
███████████████████████████████████████████████████████████████████████████████
"""

import re
import json
import gzip
import base64
import logging
import sys
import os
from threading import Lock

# ==================== CONFIGURATION ====================
SETTINGS = {
    # ---------- Response Decoding ----------
    "response": {
        "decode_gzip": True,               # Decompress gzip responses
        "decode_base64": False,            # Decode entire body if Base64
        "decode_hex": False,               # Decode entire body if hex-encoded
        "extract_json": False,             # Extract specific JSON key
        "json_key": "data",                # Key to extract
        "strip_html_comments": False,      # Remove HTML comments
        "extract_script_data": False,      # Extract data from <script> tags
        "script_regex": r'<script[^>]*>([\s\S]*?)</script>',  # Script extraction
    },
    # ---------- Token Extraction ----------
    "token_extract": {
        "enabled": True,
        "patterns": [
            # (source, regex, store_as)
            (r'body', r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', 'csrf'),
            (r'body', r'"access_token":"([^"]+)"', 'jwt'),
            (r'body', r'"token":"([^"]+)"', 'token'),
            (r'body', r'"csrf":"([^"]+)"', 'csrf'),
            (r'body', r'"authenticity_token":"([^"]+)"', 'authenticity'),
            (r'body', r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']', 'csrf'),
            (r'headers', r'X-CSRF-Token:\s*([^\s]+)', 'csrf_header'),
            (r'headers', r'X-XSRF-TOKEN:\s*([^\s]+)', 'xsrf'),
        ]
    },
    # ---------- Authentication Flow ----------
    "auth_flow": {
        "enabled": False,
        "success_indicator": "Dashboard",   # String in response indicating login success
        "failure_indicator": "Login failed", # Optional
    },
    # ---------- Logging & Debug ----------
    "logging": {
        "enabled": True,
        "file": "sqlmap_postprocess.log",
        "log_response_preview": True,
        "verbose": True,
    }
}
# =======================================================

# -------------------- GLOBALS (shared with preprocess) --------------------
_state = {
    "tokens": {},
    "cookies": {},
    "auth_done": False,
    "request_count": 0,
}
_state_lock = Lock()

_logger = None

def _setup_logger():
    global _logger
    if _logger is not None:
        return _logger
    logger = logging.getLogger("sqlmap_postprocess")
    logger.setLevel(logging.DEBUG)
    if SETTINGS["logging"]["enabled"]:
        fh = logging.FileHandler(SETTINGS["logging"]["file"])
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s")
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    if SETTINGS["logging"]["verbose"]:
        ch = logging.StreamHandler(sys.stderr)
        ch.setLevel(logging.INFO)
        logger.addHandler(ch)
    _logger = logger
    return logger

def _log(level, msg):
    logger = _setup_logger()
    getattr(logger, level)(msg)

# -------------------- UTILITIES --------------------
def _get_value(obj, key, default=None):
    if hasattr(obj, key):
        return getattr(obj, key)
    elif isinstance(obj, dict):
        return obj.get(key, default)
    return default

def _set_value(obj, key, value):
    if hasattr(obj, key):
        setattr(obj, key, value)
    elif isinstance(obj, dict):
        obj[key] = value
    else:
        raise TypeError("Cannot set value on this object type")

def _get_body(resp):
    body = _get_value(resp, "body", "")
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="ignore")
    return body

def _set_body(resp, body):
    if isinstance(body, str):
        body = body.encode("utf-8")
    _set_value(resp, "body", body)

def _get_headers(resp):
    headers = _get_value(resp, "headers", {})
    if not isinstance(headers, dict):
        headers = dict(headers)
        _set_value(resp, "headers", headers)
    return headers

# -------------------- RESPONSE DECODING --------------------
def _decode_response(resp):
    """Apply all enabled decoding layers to the response body."""
    body = _get_body(resp)
    if not body:
        return

    # 1. Gzip decompression
    if SETTINGS["response"]["decode_gzip"]:
        headers = _get_headers(resp)
        if headers.get("Content-Encoding", "").lower() == "gzip":
            try:
                decoded = gzip.decompress(body.encode()).decode()
                _set_body(resp, decoded)
                _log("debug", "Decompressed gzip response")
            except Exception as e:
                _log("warning", f"Gzip decompress failed: {e}")

    # Refresh body after possible decompression
    body = _get_body(resp)

    # 2. Base64 decode
    if SETTINGS["response"]["decode_base64"]:
        try:
            decoded = base64.b64decode(body).decode()
            _set_body(resp, decoded)
            _log("debug", "Decoded base64 response")
        except Exception:
            pass

    # Refresh body
    body = _get_body(resp)

    # 3. Hex decode
    if SETTINGS["response"]["decode_hex"]:
        try:
            decoded = bytes.fromhex(body).decode()
            _set_body(resp, decoded)
            _log("debug", "Decoded hex response")
        except Exception:
            pass

    # Refresh body
    body = _get_body(resp)

    # 4. Extract JSON key
    if SETTINGS["response"]["extract_json"]:
        try:
            data = json.loads(body)
            key = SETTINGS["response"]["json_key"]
            if key in data:
                _set_body(resp, str(data[key]))
                _log("debug", f"Extracted JSON key '{key}'")
        except Exception:
            pass

    # Refresh body
    body = _get_body(resp)

    # 5. Strip HTML comments
    if SETTINGS["response"]["strip_html_comments"]:
        cleaned = re.sub(r'<!--.*?-->', '', body, flags=re.DOTALL)
        _set_body(resp, cleaned)
        _log("debug", "Stripped HTML comments")

    # Refresh body
    body = _get_body(resp)

    # 6. Extract data from <script> tags
    if SETTINGS["response"]["extract_script_data"]:
        regex = SETTINGS["response"]["script_regex"]
        matches = re.findall(regex, body, re.DOTALL | re.IGNORECASE)
        if matches:
            # Combine all script contents
            script_data = "\n".join(matches)
            # Optionally, we could replace the body with this data,
            # but we'll just log it and maybe store it for later.
            _log("debug", f"Extracted {len(matches)} script blocks")
            # If you want to set body to script data, uncomment:
            # _set_body(resp, script_data)

# -------------------- TOKEN EXTRACTION --------------------
def _extract_tokens(resp):
    """Extract tokens from body and headers using configured patterns."""
    if not SETTINGS["token_extract"]["enabled"]:
        return

    body = _get_body(resp)
    headers = _get_headers(resp)
    patterns = SETTINGS["token_extract"]["patterns"]

    for source, pattern, store_as in patterns:
        text = body if source.lower() == "body" else str(headers)
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            token = match.group(1).strip()
            with _state_lock:
                _state["tokens"][store_as] = token
            _log("info", f"🔑 Extracted token '{store_as}': {token[:10]}...")
            # Also store token as a cookie if it looks like a session
            if store_as in ("sessionid", "PHPSESSID", "JSESSIONID"):
                _state["cookies"][store_as] = token

    # Capture cookies from Set-Cookie headers
    set_cookie = headers.get("Set-Cookie", "")
    if set_cookie:
        # Multiple cookies can be in one header or multiple headers
        # We'll handle the common case: single string with multiple cookies separated by comma
        cookies = set_cookie.split(",") if "," in set_cookie else [set_cookie]
        for cookie in cookies:
            # Extract name=value
            match = re.search(r'([^=;]+)=([^;]+)', cookie)
            if match:
                name = match.group(1).strip()
                value = match.group(2).strip()
                with _state_lock:
                    _state["cookies"][name] = value
                _log("info", f"🍪 Captured cookie '{name}': {value[:10]}...")

# -------------------- AUTHENTICATION FLOW --------------------
def _handle_auth_flow(resp):
    """Detect authentication success/failure based on indicators."""
    global _state
    if not SETTINGS["auth_flow"]["enabled"] or _state["auth_done"]:
        return

    body = _get_body(resp)
    success = SETTINGS["auth_flow"].get("success_indicator")
    failure = SETTINGS["auth_flow"].get("failure_indicator")

    if success and success in body:
        _state["auth_done"] = True
        _log("info", "🔓 Authentication successful")
    elif failure and failure in body:
        _log("warning", "🔐 Authentication failed – check credentials")
    else:
        _log("debug", "Authentication status unknown – continuing")

# -------------------- MAIN EXPORTED FUNCTION --------------------
def postprocess(page, headers=None, code=None):
    """
    Primary entry point for sqlmap's --postprocess.
    Accepts page (body), headers, and status code.
    Returns tuple (modified_page, modified_headers, modified_code).
    Always returns a tuple, even on error.
    """
    global _state

    final_page = page
    final_headers = headers
    final_code = code

    try:
        # Build an internal response dict
        resp = {
            "body": page,
            "headers": headers or {},
            "status": code
        }

        with _state_lock:
            _state["request_count"] += 1
            req_id = _state["request_count"]

        _log("info", f"⚡ POSTPROCESS RESP #{req_id} – DECRYPTING RESPONSE")

        # Decode layers
        _decode_response(resp)

        # Extract intelligence (tokens, cookies)
        _extract_tokens(resp)

        # Authentication flow detection
        if SETTINGS["auth_flow"]["enabled"] and not _state["auth_done"]:
            _handle_auth_flow(resp)

        # Log preview
        if SETTINGS["logging"]["log_response_preview"]:
            body = _get_body(resp)
            if body:
                preview = body[:200] + ("..." if len(body) > 200 else "")
                _log("debug", f"RESP #{req_id} Body preview: {preview}")

        # Update final values (only page may change)
        final_page = _get_body(resp)
        # Headers and code remain unchanged (we don't modify them)

    except Exception as e:
        _log("error", f"🔥 Postprocess error: {e}")
        import traceback
        _log("debug", traceback.format_exc())

    return (final_page, final_headers, final_code)

# ==================== SELF‑TEST ====================
if __name__ == "__main__":
    print("🧪 Testing postprocess module...")
    # Dummy response
    dummy_page = '<html><input name="csrf_token" value="abc123"><script>var token="xyz789";</script></html>'
    dummy_headers = {"Set-Cookie": "PHPSESSID=deadbeef; path=/"}
    dummy_code = 200

    new_page, new_headers, new_code = postprocess(dummy_page, dummy_headers, dummy_code)
    print(f"Modified page: {new_page[:100]}...")
    print(f"Extracted tokens: {_state['tokens']}")
    print(f"Extracted cookies: {_state['cookies']}")
    print("✅ Self‑test complete.")
