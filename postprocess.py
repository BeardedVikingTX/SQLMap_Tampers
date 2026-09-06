# postprocess.py
import re

NEW_TOKEN = None

def postprocess(resp):
    global NEW_TOKEN
    # Look for token in response body or headers
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.get("body", ""))
    if match:
        NEW_TOKEN = match.group(1)
        # Now preprocess can use this NEW_TOKEN on subsequent requests
        # (you'd need a global variable or a file to share)
        print(f"Updated CSRF token: {NEW_TOKEN}")
