<p align="center">
  <img src="images/glitch.gif" alt="Glitch effect" width="100%">
</p>

# 🛡️ SQLMap Tampers – Bearded Viking Security Forge

> **Advanced sqlmap tamper scripts for modern WAF bypass – JSON Unicode escapes, mathematical obfuscation, nested versioned comments, and random keyword splitting. Continuously updated. For authorised security testing only.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub last commit](https://img.shields.io/github/last-commit/BeardedVikingTX/SQLMap_Tampers)](https://github.com/BeardedVikingTX/SQLMap_Tampers/commits/main)

---

## 📦 What’s Inside

| Tamper Script | Description |
|---------------|-------------|
| **`json_unicode_escape.py`** | Fully fledged JSON obfuscator: Unicode/hex/octal escapes, random case, whitespace tricks, JSON/array wrapping, junk injection, and comment fragmentation – all configurable. |
| **`math_exp_obfuscator.py`** | Replaces every integer literal with a random, DBMS‑aware mathematical expression (trig, log, bitwise, etc.) drawn from 100+ templates. |
| **`nested_versioned_comments.py`** | Wraps SQL keywords in deeply nested MySQL versioned comments (`/*!50727...*/`) with random hex/base64 padding – up to 5 levels deep, with multiple DBMS fallbacks. |
| **`random_chunk_splitter.py`** | Splits SQL keywords into 2–4 fragments, inserting inline or versioned comments between them – randomness per request to defeat signature‑based WAFs. |

> **More tampers are in active development** – watch this space!

---

## 🚀 Installation (One‑Click)

We’ve made it dead simple to install all tampers into your sqlmap environment.

1. Clone the repo:
```
   git clone https://github.com/BeardedVikingTX/SQLMap_Tampers.git
   cd SQLMap_Tampers
```
2. Run the installer:
```
chmod +x install_tampers.sh
./install_tampers.sh
```
_Optionally, backup existing tampers:_
```
./install_tampers.sh --backup
```
_To copy all `.py` files in the directory:_
```
./install_tampers.sh --all
```
3. Verify they’re installed:
```
sqlmap --list-tampers | grep -E "(json_unicode_escape|math_exp_obfuscator|nested_versioned_comments|random_chunk_splitter)"
```
**Success!** Here’s what it looks like when the script does its magic:

* **Tamper Scripts BEFORE Installing Our Scripts:**
<p align="center"> 
  <img src="images/sqlmap_tampers_before_bash_script.png" alt="SQLMap Tamper Scripts BEFORE Installing Custom Scripts." width="80%"> 
</p>

* **Installing OUR Tamper Scripts:** 
<p align="center">
  <img src="images/installed_tampers.png" alt="Installing Custom Tamper Scripts." width="80%">
</p>

* **Tamper Scripts AFTER Installing Our Scripts:**
<p align="center">
  <img src="images/sqlmap_tampers_after_bash_script.png" alt="SQLMap Tamper Scripts AFTER Installing Custom Scripts." width="80%">
</p>

## 🎯 Usage Examples
Once installed, use them individually or in combination:
```
# Single tamper
sqlmap -u "http://target.com?id=1" --tamper=json_unicode_escape

# Stack multiple tampers (order matters)
sqlmap -u "http://target.com?id=1" \
       --tamper=json_unicode_escape,math_exp_obfuscator,nested_versioned_comments,random_chunk_splitter

# With other built‑in tampers
sqlmap -u "http://target.com?id=1" \
       --tamper=json_unicode_escape,space2comment,randomcase
```

## 🧠 Why These Tampers?
* **SON APIs** – the `json_unicode_escape` tamper deals with the quirks of JSON parsers and WAFs that don’t handle Unicode escapes correctly.
* **WAF evasion** – our tampers combine multiple layers (math obfuscation, comment nesting, keyword fragmentation) to bypass even advanced WAFs.
* **DBMS awareness** – scripts detect the backend and adapt (MySQL, PostgreSQL, MSSQL, Oracle) so they never break your SQL.
* **Randomisation** – each request is unique; signature‑based detection becomes ineffective.

## 🔧 Customisation
For the JSON tamper (`json_unicode_escape.py`), edit the `SETTINGS` dict at the top to enable/disable individual techniques:
```
SETTINGS = {
    'unicode_escape': True,
    'hex_escape': False,
    'random_case': True,
    'json_wrap': True,
    # ... etc.
}
```

## 🔧 Pre/Post‑Processing Hooks
Beyond tamper scripts, sqlmap offers **pre‑processing** and **post‑processing** hooks that let you **modify every request before it’s sent** and **inspect/alter every response** before sqlmap processes it.  

This is invaluable for:
* **Session management** – _automatically extract and inject CSRF tokens, JWTs, or nonces._  
* **Custom encoding** – _encode payloads in Base64, hex, or your own scheme._  
* **Header rotation** – _spoof `X‑Forwarded‑For`, rotate User‑Agents, add timestamps._  
* **Response decoding** – _decompress gzip, unwrap Base64, extract JSON values._  
* **Multi‑step authentication** – _handle login flows programmatically._  

We provide **two levels** of hooks:

## 🧩 Simple Examples: `preprocess.py` & `postprocess.py`
These are minimal, single‑purpose scripts that demonstrate the hook concept:
* `preprocess.py` – Injects a static CSRF token into every POST request and adds a custom header.
* `postprocess.py` – Extracts a CSRF token from the response body and stores it (for the next request).
Usage:
```
sqlmap -u "http://target.com/page?id=1" \
       --preprocess=preprocess.py \
       --postprocess=postprocess.py
```
These are **starter templates** – you can adapt them to your needs, but for serious work, we recommend the advanced `hooks.py` below.

## 🚀 Advanced All‑in‑One: `hooks.py`

`hooks.py` is a **production‑grade**, fully configurable pre/post‑processing engine that consolidates everything into a single file.
**Key features:**
* **Token extraction & injection** – define regex patterns to pull tokens from response body/headers, then inject them into subsequent requests as parameters, headers, or cookies.
* **Payload encoding** – encode injection payloads with Base64, hex, double URL‑encode, or custom methods.
* **Header manipulation** – add static headers, rotate User‑Agent, add timestamps.
* **Response decoding** – handle gzip, Base64, JSON extraction, and strip HTML comments.
* **Comprehensive logging** – log all modifications to a file and console for debugging.
* **Multi‑step authentication** – skeleton for login flows (can be extended with requests library).
  
**How to use it:**
1. Save `hooks.py` in your working directory.
2. Edit the `SETTINGS` dict at the top to match your target (enable/disable features, adjust regex patterns, choose encoding, etc.).
3. Run sqlmap with both flags pointing to the same file:
```
sqlmap -u "http://target.com/page?id=1" \
       --preprocess=hooks.py \
       --postprocess=hooks.py \
       --batch --level=5
```

***Why it’s important:***
* **Handles dynamic tokens** – no more manual cookie/token updates; the hooks do it live.
* **Defeats WAFs** – encode payloads on the fly to bypass signature‑based filters.
* **Saves time** – eliminates the need for separate `--cookie`, `--headers`, or `--data` fiddling.

Customisation example – inside `hooks.py`, you’ll find:
```
SETTINGS = {
    "token_extract": {
        "enabled": True,
        "patterns": [
            (r'body', r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', 'csrf'),
            ...
        ],
        "inject_into": {
            "csrf": {"target": "data", "param": "csrf_token"},
            ...
        }
    },
    "payload_encoding": {
        "enabled": True,
        "method": "base64",   # or 'hex', 'double_url', 'custom'
    },
    ...
}
```
Simply tweak these settings to fit your target, and you’re good to go.  
  
**Pro tip:** _combine the hooks with your favourite tampers for maximum evasion:_
```
sqlmap -u "http://target.com/api?id=1" \
       --preprocess=hooks.py --postprocess=hooks.py \
       --tamper=json_unicode_escape,math_exp_obfuscator
```
This gives you ***unmatched control*** over every aspect of the request/response cycle.

# ⚠️ Disclaimer
***Use these tools only on systems you own or have explicit written permission to test.***
_The author (Bearded Viking / Bearded Viking Security Forge) assumes **no liability** for any misuse or damage caused by these scripts. They are provided "AS IS" without warranty of any kind._

# 📜 License
This project is licensed under the MIT License – see the [LICENSE.md[(LICENSE.md) file for details.

# 👨‍💻 About the Author

<p align="center>
  <img src="images/hackers_in_the_zone.gif" alt="Hackers in the Zone" width="45%">
</p>

**Bearded Viking** (BeardedVikingTX) – Security researcher, penetration tester, and open‑source contributor.  
* 🌐 [Web](https://beardedviking.org)  
* 🎥 [TikTok](https://www.tiktok.com/@beardedvikingtx)  
* 👨‍💻 [LinkedIn](https://www.linkedin.com/in/bearded-viking-3112a8431/)  
* 📘 [Facebook](https://www.facebook.com/BeardedVikingTX)  
* ✒️ [Medium](https://beardedviking.medium.com/)  

# 🧩 Stay Tuned
We’re constantly adding new tampers and enhancing existing ones.
Star ⭐ the repo to stay updated, and feel free to open issues or PRs with your own ideas!
<p align="center"> 
  <img src="images/matrix_female_animated.gif" alt="Matrix hacker" width="45%"> 
</p>

**Happy (`ethical`) hacking! 🛡️**
