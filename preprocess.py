# preprocess.py
import re
from bs4 import BeautifulSoup  # or use regex

# You might fetch a token from a previous response, but for simplicity:
TOKEN = "abc123"  # In reality, you'd extract it in postprocess and store globally

def preprocess(req):
    # Inject token into every POST body
    if req.get("method") == "POST":
        body = req.get("data", "")
        # Append or replace token parameter
        body += "&csrf_token=" + TOKEN
        req["data"] = body
    # Or add a custom header
    req["headers"]["X-Requested-With"] = "XMLHttpRequest"
