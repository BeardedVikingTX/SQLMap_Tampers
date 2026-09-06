#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced sqlmap pre/post‑processing hooks.
Usage:
    sqlmap -u "http://target.com/page?id=1" \
           --preprocess=hooks.py \
           --postprocess=hooks.py

Configure the SETTINGS dict below to match your target.
"""

import re
import json
import gzip
import base64
import urllib.parse
import time
import hashlib
import random
import logging
from threading import Lock
from collections import defaultdict

# ==================== CONFIGURATION ====================
SETTINGS = {
    # ---------- Session & Tokens ----------
    "token_extract": {
        "enabled": True,
        "patterns": [
            # Regex patterns to find tokens in response body/headers
            # Format: (source, regex, store_as)
            # source: 'body' or 'headers' (case-insensitive)
            (r'body', r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', 'csrf'),
            (r'body', r'"access_token":"([^"]+)"', 'jwt'),
            (r'headers', r'X-CSRF-Token:\s*([^\s]+)', 'csrf_header'),
        ],
        "inject_into": {
            # Where to inject the stored token on next requests
            "csrf": {"target": "data", "param": "csrf_token"},
            "jwt":   {"target": "headers", "param": "Authorization", "prefix": "Bearer "},
        }
    },

    # ---------- Payload Encoding ----------
    "payload_encoding": {
        "enabled": True,
        # Available: 'base64', 'hex', 'double_url', 'custom'
        "method": "base64",
        # If 'custom', define a function below in custom_encode()
        "wrap_json": False,          # Wrap entire payload in JSON: {"input":"<payload>"}
        "wrap_xml": False,           # Wrap in XML: <user><input><payload></input></user>
        "xml_root": "user",
        "xml_node": "input",
    },

    # ---------- Header Manipulation ----------
    "headers": {
        "add": {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
        },
        "randomize_user_agent": True,   # Rotate user-agent per request
        "add_timestamp": True,          # Add X-Request-Time header
    },

    # ---------- Response Handling ----------
    "response": {
        "decode_gzip": True,
        "decode_base64": False,         # If the whole body is base64-encoded
        "extract_json": False,          # Parse JSON and return only a specific key
        "json_key": "data",             # Key to extract
        "strip_html_comments": False,   # Remove HTML comments for cleaner detection
    },

    # ---------- Logging & Debugging ----------
    "logging": {
        "enabled": True,
        "file": "sqlmap_hooks.log",
        "log_request_headers": True,
        "log_response_preview": True,
        "log_payload_changes": True,
    },

    # ---------- Advanced: Multi-step Auth ----------
    "auth_flow": {
        "enabled": False,
        "login_url": "https://target.com/login",
        "login_data": {"username": "admin", "password": "pass"},
        "success_indicator": "Dashboard",   # String in response indicating success
        "session_cookie": "sessionid",      # Cookie name to capture and reuse
    }
}
# =======================================================

# -------------------- GLOBALS --------------------
_state = {
    "tokens": {},               # store extracted tokens
    "cookies": {},              # store session cookies
    "auth_done": False,
    "request_count": 0,
}
_state_lock = Lock()
_logger = None

# -------------------- LOGGING SETUP --------------------
def _setup_logger():
    global _logger
    if _logger is not None:
        return _logger
    logger = logging.getLogger("sqlmap_hooks")
    logger.setLevel(logging.DEBUG)
    if SETTINGS["logging"]["enabled"]:
        fh = logging.FileHandler(SETTINGS["logging"]["file"])
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    # Also print to stderr so sqlmap shows it
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    logger.addHandler(ch)
    _logger = logger
    return logger

def _log(level, msg):
    logger = _setup_logger()
    getattr(logger, level)(msg)

# -------------------- UTILITY FUNCTIONS --------------------
def _get_value(obj, key, default=None):
    """Safely get attribute or dict key."""
    if hasattr(obj, key):
        return getattr(obj, key)
    elif isinstance(obj, dict):
        return obj.get(key, default)
    return default

def _set_value(obj, key, value):
    """Safely set attribute or dict key."""
    if hasattr(obj, key):
        setattr(obj, key, value)
    elif isinstance(obj, dict):
        obj[key] = value
    else:
        raise TypeError("Cannot set value on this object type")

def _get_body(req):
    """Get request body as string (handles bytes)."""
    body = _get_value(req, "data", "")
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="ignore")
    return body

def _set_body(req, body):
    """Set request body (converts to bytes if needed)."""
    if isinstance(body, str):
        body = body.encode("utf-8")
    _set_value(req, "data", body)

def _get_headers(req):
    """Get headers dict, ensuring it's mutable."""
    headers = _get_value(req, "headers", {})
    if not isinstance(headers, dict):
        headers = dict(headers)  # copy
        _set_value(req, "headers", headers)
    return headers

def _get_url(req):
    return _get_value(req, "url", "")

def _set_url(req, url):
    _set_value(req, "url", url)

# -------------------- CUSTOM ENCODING (if needed) --------------------
def custom_encode(payload):
    """User-defined custom encoding."""
    # Example: reverse string and ROT13
    return payload[::-1].encode("rot13")

# -------------------- PREPROCESS --------------------
def preprocess(req):
    """Main preprocessing hook."""
    global _state
    with _state_lock:
        _state["request_count"] += 1
        req_id = _state["request_count"]

    _log("info", f"--- PREPROCESS REQ #{req_id} ---")

    # 1. Update headers with static additions
    _inject_static_headers(req)

    # 2. Rotate User-Agent
    if SETTINGS["headers"]["randomize_user_agent"]:
        _randomize_user_agent(req)

    # 3. Add timestamp header
    if SETTINGS["headers"]["add_timestamp"]:
        headers = _get_headers(req)
        headers["X-Request-Time"] = str(int(time.time()))

    # 4. Inject stored tokens
    _inject_tokens(req)

    # 5. Encode payload (if injection parameter exists)
    _encode_payload(req)

    # 6. Wrap payload in JSON/XML (if enabled)
    _wrap_payload(req)

    # 7. Log modified request
    if SETTINGS["logging"]["log_request_headers"]:
        _log("debug", f"Req #{req_id} URL: {_get_url(req)}")
        _log("debug", f"Req #{req_id} Headers: {_get_headers(req)}")
        body = _get_body(req)
        if body:
            preview = body[:200] + ("..." if len(body) > 200 else "")
            _log("debug", f"Req #{req_id} Body preview: {preview}")

def _inject_static_headers(req):
    headers = _get_headers(req)
    for k, v in SETTINGS["headers"]["add"].items():
        if k not in headers:  # don't override existing
            headers[k] = v

def _randomize_user_agent(req):
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36",
    ]
    headers = _get_headers(req)
    headers["User-Agent"] = random.choice(user_agents)

def _inject_tokens(req):
    """Inject previously extracted tokens into request."""
    if not SETTINGS["token_extract"]["enabled"]:
        return
    tokens = _state["tokens"]
    inject_map = SETTINGS["token_extract"]["inject_into"]
    for token_name, token_value in tokens.items():
        if token_name in inject_map:
            cfg = inject_map[token_name]
            target = cfg["target"]
            param = cfg["param"]
            prefix = cfg.get("prefix", "")
            if target == "data":
                body = _get_body(req)
                # Append or replace parameter
                if body:
                    # naive append; better to parse and update
                    if "=" in body:
                        body += "&"
                    body += f"{param}={urllib.parse.quote_plus(prefix + token_value)}"
                    _set_body(req, body)
                else:
                    _set_body(req, f"{param}={urllib.parse.quote_plus(prefix + token_value)}")
            elif target == "headers":
                headers = _get_headers(req)
                headers[param] = prefix + token_value

def _encode_payload(req):
    """Encode the injection parameter value."""
    if not SETTINGS["payload_encoding"]["enabled"]:
        return
    method = SETTINGS["payload_encoding"]["method"]
    # We'll try to find the injection point: usually the first parameter in URL or body.
    # sqlmap typically sets the payload in the 'parameters' dict or in 'data'.
    # Let's handle both.
    params = _get_value(req, "parameters", None)
    if isinstance(params, dict):
        for key, value in list(params.items()):
            if isinstance(value, str):
                encoded = _apply_encoding(value, method)
                params[key] = encoded
                _log("debug", f"Encoded param {key} using {method}")

    # Also check if there is raw data (POST)
    body = _get_body(req)
    if body and "=" in body:  # likely key=value
        # Try to split and encode each value
        parts = body.split("&")
        new_parts = []
        for part in parts:
            if "=" in part:
                k, v = part.split("=", 1)
                v = urllib.parse.unquote_plus(v)
                encoded = _apply_encoding(v, method)
                new_parts.append(f"{k}={urllib.parse.quote_plus(encoded)}")
            else:
                new_parts.append(part)
        _set_body(req, "&".join(new_parts))

def _apply_encoding(value, method):
    if method == "base64":
        return base64.b64encode(value.encode()).decode()
    elif method == "hex":
        return value.encode().hex()
    elif method == "double_url":
        return urllib.parse.quote(urllib.parse.quote(value))
    elif method == "custom":
        return custom_encode(value)
    else:
        return value

def _wrap_payload(req):
    """Wrap entire body or parameter in JSON/XML."""
    wrap_json = SETTINGS["payload_encoding"]["wrap_json"]
    wrap_xml = SETTINGS["payload_encoding"]["wrap_xml"]
    if not (wrap_json or wrap_xml):
        return

    body = _get_body(req)
    if not body:
        return

    if wrap_json:
        # Assume the whole body is a parameter value; wrap it
        # Or if body is key=value, we keep the key and wrap the value.
        # Simple approach: treat body as raw payload and wrap.
        wrapped = json.dumps({"input": body})
        _set_body(req, wrapped)
        # Update Content-Type
        headers = _get_headers(req)
        headers["Content-Type"] = "application/json"
        _log("debug", "Wrapped payload in JSON")

    elif wrap_xml:
        root = SETTINGS["payload_encoding"]["xml_root"]
        node = SETTINGS["payload_encoding"]["xml_node"]
        wrapped = f"<{root}><{node}>{body}</{node}></{root}>"
        _set_body(req, wrapped)
        headers = _get_headers(req)
        headers["Content-Type"] = "application/xml"
        _log("debug", "Wrapped payload in XML")

# -------------------- POSTPROCESS --------------------
def postprocess(resp):
    """Main postprocessing hook."""
    global _state
    with _state_lock:
        req_id = _state["request_count"]

    _log("info", f"--- POSTPROCESS RESP #{req_id} ---")

    # 1. Decode response if needed
    _decode_response(resp)

    # 2. Extract tokens
    _extract_tokens(resp)

    # 3. Handle authentication flow (if enabled)
    if SETTINGS["auth_flow"]["enabled"] and not _state["auth_done"]:
        _handle_auth_flow(resp)

    # 4. Log response preview
    if SETTINGS["logging"]["log_response_preview"]:
        body = _get_body(resp)
        if body:
            preview = body[:200] + ("..." if len(body) > 200 else "")
            _log("debug", f"Resp #{req_id} Body preview: {preview}")

def _decode_response(resp):
    """Decode gzip, base64, or extract JSON key."""
    body = _get_body(resp)
    if not body:
        return

    if SETTINGS["response"]["decode_gzip"]:
        # Check if content-encoding is gzip
        headers = _get_headers(resp)
        if headers.get("Content-Encoding", "").lower() == "gzip":
            try:
                decoded = gzip.decompress(body.encode()).decode()
                _set_body(resp, decoded)
                _log("debug", "Decompressed gzip response")
            except Exception as e:
                _log("warning", f"Gzip decompress failed: {e}")

    if SETTINGS["response"]["decode_base64"]:
        try:
            decoded = base64.b64decode(body).decode()
            _set_body(resp, decoded)
            _log("debug", "Decoded base64 response")
        except Exception:
            pass

    if SETTINGS["response"]["extract_json"]:
        try:
            data = json.loads(body)
            key = SETTINGS["response"]["json_key"]
            if key in data:
                _set_body(resp, str(data[key]))
                _log("debug", f"Extracted JSON key '{key}'")
        except Exception:
            pass

    if SETTINGS["response"]["strip_html_comments"]:
        cleaned = re.sub(r'<!--.*?-->', '', body, flags=re.DOTALL)
        _set_body(resp, cleaned)
        _log("debug", "Stripped HTML comments")

def _extract_tokens(resp):
    """Extract tokens from response using configured patterns."""
    if not SETTINGS["token_extract"]["enabled"]:
        return

    body = _get_body(resp)
    headers = _get_headers(resp)
    patterns = SETTINGS["token_extract"]["patterns"]

    for source, pattern, store_as in patterns:
        text = body if source.lower() == "body" else str(headers)
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            token = match.group(1)
            with _state_lock:
                _state["tokens"][store_as] = token
            _log("info", f"Extracted token '{store_as}': {token[:10]}...")

    # Also capture cookies from Set-Cookie
    set_cookie = headers.get("Set-Cookie", "")
    if set_cookie:
        # Simple extraction: sessionid=abc123; path=/
        match = re.search(r'(sessionid|PHPSESSID|JSESSIONID)=([^;]+)', set_cookie, re.I)
        if match:
            cookie_name = match.group(1)
            cookie_value = match.group(2)
            with _state_lock:
                _state["cookies"][cookie_name] = cookie_value
            _log("info", f"Captured cookie '{cookie_name}': {cookie_value[:10]}...")

def _handle_auth_flow(resp):
    """Perform multi-step authentication if not already done."""
    global _state
    if _state["auth_done"]:
        return

    cfg = SETTINGS["auth_flow"]
    # If the response contains success indicator, mark auth as done
    body = _get_body(resp)
    if cfg["success_indicator"] in body:
        _state["auth_done"] = True
        _log("info", "Authentication successful")
        return

    # If not authenticated, try to login by sending a new request
    # Note: sqlmap doesn't allow sending arbitrary requests from hooks easily.
    # We'd need to use requests library. This is advanced.
    # We'll just log a warning.
    _log("warning", "Auth not done yet - you may need to implement login via requests library")

# -------------------- HELPER TO GET BODY FROM RESP --------------------
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

# ==================== MAIN ENTRY POINT (for testing) ====================
if __name__ == "__main__":
    # Quick test with dummy objects
    class DummyReq:
        url = "http://test.com?id=1"
        method = "GET"
        headers = {}
        data = ""
        parameters = {"id": "1 UNION SELECT 1"}

    class DummyResp:
        status = 200
        headers = {"Content-Type": "text/html"}
        body = '<input name="csrf_token" value="abc123">'

    req = DummyReq()
    print("=== PREPROCESS ===")
    preprocess(req)
    print(f"Modified body: {req.data}")

    resp = DummyResp()
    print("\n=== POSTPROCESS ===")
    postprocess(resp)
    print(f"Extracted tokens: {_state['tokens']}")
