#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
███████████████████████████████████████████████████████████████████████████████
███  H O O K S   –  THE CYBER ORCHESTRATOR                            ███
███  ULTIMATE FIX: No header coercion – preserve original objects.    ███
███████████████████████████████████████████████████████████████████████████████
"""

import sys
import os

# Add current directory to path
_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

# Import the engines
try:
    from preprocess import preprocess as _preprocess_engine
    from postprocess import postprocess as _postprocess_engine
except ImportError as e:
    sys.stderr.write(f"🔥 ERROR: Could not import preprocess/postprocess: {e}\n")
    sys.stderr.write("   Make sure 'preprocess.py' and 'postprocess.py' are in the same directory.\n")
    raise

__version__ = "2.0.0-ultimate"
__author__ = "Bearded Viking (BeardedVikingTX) | Bearded Viking Security Forge"

# ==================== WRAPPER FUNCTIONS ====================

def preprocess(req):
    """
    Wrapper for sqlmap's --preprocess.
    Calls the actual engine from preprocess.py.
    """
    try:
        return _preprocess_engine(req)
    except Exception as e:
        sys.stderr.write(f"🔥 PREPROCESS ERROR: {e}\n")
        raise

def postprocess(page, headers=None, code=None):
    """
    Wrapper for sqlmap's --postprocess.
    GUARANTEES a tuple of 3 elements is returned.
    DOES NOT convert headers – preserves original object.
    """
    try:
        # Call the engine – it should return (page, headers, code)
        result = _postprocess_engine(page, headers, code)

        # If result is a tuple of 3, use it directly
        if isinstance(result, tuple) and len(result) == 3:
            return result

        # Fallback – keep original values
        sys.stderr.write(f"⚠️ WARNING: Engine returned {type(result)} – using original values.\n")
        return (page, headers, code)

    except Exception as e:
        sys.stderr.write(f"🔥 POSTPROCESS ERROR: {e}\n")
        import traceback
        sys.stderr.write(traceback.format_exc())
        return (page, headers, code)

# ==================== SELF‑TEST ====================
if __name__ == "__main__":
    print("🧪 Testing Hooks Orchestrator...")
    print(f"   Version: {__version__}")

    class DummyReq:
        url = "http://test.com?id=1"
        method = "GET"
        headers = {}
        data = ""
        parameters = {"id": "1 UNION SELECT 1"}

    print("\n🔹 Testing preprocess...")
    req = DummyReq()
    preprocess(req)
    print(f"   Modified body: {req.data[:100] if req.data else '(empty)'}...")

    print("\n🔹 Testing postprocess...")
    class DummyResp:
        status = 200
        headers = {"Content-Type": "text/html"}  # simplified for test
        body = '<input name="csrf_token" value="abc123">'

    resp = DummyResp()
    new_page, new_headers, new_code = postprocess(resp.body, resp.headers, resp.status)
    print(f"   Modified page: {new_page[:100] if new_page else '(empty)'}...")
    print(f"   Headers type: {type(new_headers)}")
    print(f"   Code: {new_code}")

    print("\n✅ Self‑test passed. Hooks ready for sqlmap.")
