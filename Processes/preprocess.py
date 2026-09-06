#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
███████████████████████████████████████████████████████████████████████████████
███  PR E P R O C E S S   –  ULTIMATE REQUEST CYBER OVERRIDE ENGINE     ███
███  Now with intelligent encoding, header preservation, and full WAF   ███
███  evasion. Skips critical headers (Host, Connection, etc.) to avoid  ███
███  server errors. Injects tokens, rotates User‑Agent, adds timestamps.███
███  This is the pinnacle of sqlmap preprocessing.                     ███
███████████████████████████████████████████████████████████████████████████████
"""

import os
import re
import json
import base64
import urllib.parse
import time
import random
import logging
import sys
from threading import Lock

# ==================== CONFIGURATION ====================
SETTINGS = {
    # ---------- Header Warfare ----------
    "headers": {
        "add": {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
        },
        "randomize_user_agent": True,
        "add_timestamp": True,
        "custom_headers_file": "headers.txt",
        # Headers that should NEVER be modified, encoded, or injected into
        "protected_headers": [
            "host",
            "content-length",
            "connection",
            "transfer-encoding",
            "content-encoding",
            "accept-encoding",
            "expect",
            "upgrade",
        ],
    },
    # ---------- Payload Encoding ----------
    "payload_encoding": {
        "enabled": True,
        "method": "base64",          # base64 | hex | double_url | custom
        "wrap_json": False,
        "wrap_xml": False,
        "xml_root": "user",
        "xml_node": "input",
    },
    # ---------- Token Injection ----------
    "token_injection": {
        "enabled": True,
        "inject_into": {
            "csrf": {"target": "data", "param": "csrf_token"},
            "jwt":   {"target": "headers", "param": "Authorization", "prefix": "Bearer "},
        }
    },
    # ---------- Logging & Debug ----------
    "logging": {
        "enabled": True,
        "file": "sqlmap_preprocess.log",
        "log_request_headers": True,
        "log_payload_changes": True,
        "verbose": True,
    }
}
# =======================================================

# -------------------- GLOBALS (shared) --------------------
_state = {
    "tokens": {},
    "cookies": {},
    "request_count": 0,
}
_state_lock = Lock()

_logger = None

def _setup_logger():
    global _logger
    if _logger is not None:
        return _logger
    logger = logging.getLogger("sqlmap_preprocess")
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

def _get_body(req):
    body = _get_value(req, "data", "")
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="ignore")
    return body

def _set_body(req, body):
    if isinstance(body, str):
        body = body.encode("utf-8")
    _set_value(req, "data", body)

def _get_headers(req):
    headers = _get_value(req, "headers", {})
    if not isinstance(headers, dict):
        headers = dict(headers)
        _set_value(req, "headers", headers)
    return headers

def _get_url(req):
    return _get_value(req, "url", "")

def _is_protected_header(name):
    """Check if a header is protected (should not be modified)."""
    protected = SETTINGS["headers"].get("protected_headers", [])
    return name.lower() in [p.lower() for p in protected]

# ==================== CUSTOM HEADER LOADER ====================
def _load_custom_headers():
    header_file = SETTINGS["headers"].get("custom_headers_file", "headers.txt")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    filepath = os.path.join(script_dir, header_file)
    if not os.path.isfile(filepath):
        _log("debug", f"Custom headers file '{filepath}' not found – using defaults.")
        return {}

    custom_headers = {}
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" in line:
                    key, val = line.split(":", 1)
                    custom_headers[key.strip()] = val.strip()
        if custom_headers:
            _log("info", f"✅ Loaded {len(custom_headers)} custom headers from '{filepath}'")
        else:
            _log("info", "ℹ️ Custom headers file is empty – using defaults.")
    except Exception as e:
        _log("warning", f"⚠️ Could not read custom headers file: {e}")
    return custom_headers

# ==================== PREPROCESS CORE ====================
def _inject_custom_headers(req):
    custom = _load_custom_headers()
    if custom:
        headers = _get_headers(req)
        for k, v in custom.items():
            if k not in headers and not _is_protected_header(k):
                headers[k] = v
                _log("debug", f"Injected custom header: {k}: {v}")
            elif _is_protected_header(k):
                _log("debug", f"Skipping protected header '{k}' from custom injection")

def _inject_static_headers(req):
    headers = _get_headers(req)
    for k, v in SETTINGS["headers"]["add"].items():
        if k not in headers and not _is_protected_header(k):
            headers[k] = v

def _randomize_user_agent(req):
    ua_list = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36",
    ]
    headers = _get_headers(req)
    headers["User-Agent"] = random.choice(ua_list)

def _add_timestamp(req):
    headers = _get_headers(req)
    headers["X-Request-Time"] = str(int(time.time()))

# ---------------- TOKEN INJECTION ----------------
def _inject_tokens(req):
    if not SETTINGS["token_injection"]["enabled"]:
        return
    tokens = _state.get("tokens", {})
    if not tokens:
        return

    inject_map = SETTINGS["token_injection"]["inject_into"]
    headers = _get_headers(req)
    body = _get_body(req)

    for token_name, token_value in tokens.items():
        if token_name not in inject_map:
            continue

        cfg = inject_map[token_name]
        target = cfg["target"]
        param = cfg["param"]
        prefix = cfg.get("prefix", "")
        full_value = prefix + token_value

        # Skip if target is header and param is protected
        if target == "headers" and _is_protected_header(param):
            _log("debug", f"Skipping injection into protected header '{param}'")
            continue

        if target == "data":
            # Inject into POST data
            if body:
                params = {}
                for part in body.split("&"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        params[k] = urllib.parse.unquote_plus(v)
                params[param] = full_value
                new_body = "&".join(f"{k}={urllib.parse.quote_plus(v)}" for k, v in params.items())
                _set_body(req, new_body)
                _log("debug", f"Injected token '{param}' into data: {full_value[:10]}...")
            else:
                _set_body(req, f"{param}={urllib.parse.quote_plus(full_value)}")
                _log("debug", f"Created new data with token '{param}'")

        elif target == "headers":
            headers[param] = full_value
            _log("debug", f"Injected token into header '{param}': {full_value[:10]}...")
        else:
            _log("warning", f"Unknown injection target '{target}' for token '{token_name}'")

# ---------------- PAYLOAD ENCODING ----------------
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

def custom_encode(payload):
    import codecs
    return codecs.encode(payload[::-1], 'rot_13')

def _encode_payload(req):
    if not SETTINGS["payload_encoding"]["enabled"]:
        return

    method = SETTINGS["payload_encoding"]["method"]

    # 1) Encode parameters (sqlmap's internal 'parameters' dict)
    params = _get_value(req, "parameters", None)
    if isinstance(params, dict):
        for key, value in list(params.items()):
            if isinstance(value, str):
                try:
                    encoded = _apply_encoding(value, method)
                    params[key] = encoded
                    _log("debug", f"Encoded param '{key}' using {method}")
                except Exception as e:
                    _log("warning", f"Failed to encode param '{key}': {e}")

    # 2) Encode raw body (POST data) – but skip if body contains protected headers
    body = _get_body(req)
    if body:
        # If the body is a key=value string, encode only values
        if "=" in body and "&" in body:
            parts = body.split("&")
            new_parts = []
            for part in parts:
                if "=" in part:
                    k, v = part.split("=", 1)
                    v = urllib.parse.unquote_plus(v)
                    # Skip if the key is a protected header (shouldn't happen in body, but just in case)
                    if _is_protected_header(k):
                        new_parts.append(part)
                        continue
                    try:
                        encoded = _apply_encoding(v, method)
                    except Exception as e:
                        _log("warning", f"Failed to encode value for key '{k}': {e}")
                        encoded = v
                    new_parts.append(f"{k}={urllib.parse.quote_plus(encoded)}")
                else:
                    new_parts.append(part)
            new_body = "&".join(new_parts)
            _set_body(req, new_body)
            _log("debug", f"Encoded raw body using {method}")
        else:
            # Single value – encode it if it's not a protected header
            if not _is_protected_header(body.strip()):
                try:
                    encoded = _apply_encoding(body, method)
                    _set_body(req, encoded)
                    _log("debug", f"Encoded entire raw body using {method}")
                except Exception as e:
                    _log("warning", f"Failed to encode entire body: {e}")
            else:
                _log("debug", "Skipped encoding of protected header-like body")

# ---------------- PAYLOAD WRAPPING ----------------
def _wrap_payload(req):
    wrap_json = SETTINGS["payload_encoding"]["wrap_json"]
    wrap_xml = SETTINGS["payload_encoding"]["wrap_xml"]
    if not (wrap_json or wrap_xml):
        return

    body = _get_body(req)
    if not body:
        return

    headers = _get_headers(req)

    if wrap_json:
        try:
            wrapped = json.dumps({"input": body})
            _set_body(req, wrapped)
            headers["Content-Type"] = "application/json"
            _log("debug", "Wrapped payload in JSON")
        except Exception as e:
            _log("warning", f"JSON wrapping failed: {e}")

    elif wrap_xml:
        root = SETTINGS["payload_encoding"]["xml_root"]
        node = SETTINGS["payload_encoding"]["xml_node"]
        try:
            import xml.sax.saxutils as saxutils
            escaped_body = saxutils.escape(body)
            wrapped = f"<{root}><{node}>{escaped_body}</{node}></{root}>"
            _set_body(req, wrapped)
            headers["Content-Type"] = "application/xml"
            _log("debug", "Wrapped payload in XML")
        except Exception as e:
            _log("warning", f"XML wrapping failed: {e}")

# ==================== MAIN EXPORTED FUNCTION ====================
def preprocess(req):
    """
    Primary entry point for sqlmap's --preprocess.
    Modifies the request object in‑place.
    """
    global _state
    with _state_lock:
        _state["request_count"] += 1
        req_id = _state["request_count"]

    _log("info", f"⚡ PREPROCESS REQ #{req_id} – INITIALIZING CYBER OVERRIDE")

    # LAYER 1: Custom headers from user file
    _inject_custom_headers(req)

    # LAYER 2: Static headers
    _inject_static_headers(req)

    # LAYER 3: User‑Agent rotation
    if SETTINGS["headers"]["randomize_user_agent"]:
        _randomize_user_agent(req)

    # LAYER 4: Timestamp
    if SETTINGS["headers"]["add_timestamp"]:
        _add_timestamp(req)

    # LAYER 5: Token injection (from previous responses)
    _inject_tokens(req)

    # LAYER 6: Payload encoding
    _encode_payload(req)

    # LAYER 7: Payload wrapping
    _wrap_payload(req)

    # LOG request details (if verbose)
    if SETTINGS["logging"]["log_request_headers"]:
        _log("debug", f"REQ #{req_id} URL: {_get_url(req)}")
        _log("debug", f"REQ #{req_id} Headers: {_get_headers(req)}")
        body = _get_body(req)
        if body:
            preview = body[:200] + ("..." if len(body) > 200 else "")
            _log("debug", f"REQ #{req_id} Body preview: {preview}")

    _log("info", f"✅ REQ #{req_id} – PREPROCESS COMPLETE")
