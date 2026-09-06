#!/usr/bin/env python3
import subprocess
import re
from collections import defaultdict

# Run sqlmap and capture output
try:
    output = subprocess.check_output(['sqlmap', '--list-tampers'], text=True)
except Exception as e:
    print(f"Error running sqlmap: {e}")
    exit(1)

# Parse lines that start with "* " and contain ".py - "
pattern = re.compile(r'^\* (\w+)\.py - (.+)$')
tampers = []  # list of (name, description)

for line in output.splitlines():
    m = pattern.match(line)
    if m:
        tampers.append((m.group(1), m.group(2).strip()))

# Define category rules (keywords checked in description, case-insensitive)
categories = {
    'mysql':        ['mysql'],
    'mssql':        ['mssql', 'ms sql', 'sql server'],
    'oracle':       ['oracle'],
    'postgresql':   ['postgresql', 'postgres'],
    'bypass':       ['waf', 'bypass', 'firewall', '403', 'cloudflare',
                     'lua', 'nginx', 'modsecurity', 'varnish', 'xforwarded'],
    # "generic" will be assigned to tampers not matching any DBMS-specific rule (see below)
}

# Build a dictionary: category -> list of tamper names
grouped = defaultdict(list)

for name, desc in tampers:
    # Always add to "all"
    grouped['all'].append(name)

    desc_lower = desc.lower()
    matched_db = False

    for cat, keywords in categories.items():
        if cat == 'bypass':
            continue  # handle bypass separately
        if any(kw in desc_lower for kw in keywords):
            grouped[cat].append(name)
            matched_db = True

    # Bypass: check if any bypass keyword matches
    if any(kw in desc_lower for kw in categories['bypass']):
        grouped['bypassing_403'].append(name)

    # If no DBMS-specific match, put into "generic"
    if not matched_db:
        grouped['generic'].append(name)

# Write each category as a comma-separated list (one line)
for cat, names in grouped.items():
    # Remove duplicates (in case a tamper matched multiple DBMS)
    unique_names = list(dict.fromkeys(names))  # preserves order
    filename = f"{cat}_tampers.txt"
    with open(filename, 'w') as f:
        f.write(','.join(unique_names))
    print(f"Written {len(unique_names)} tampers to {filename}")
