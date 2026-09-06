#!/usr/bin/env bash
#===============================================================================
# Install custom sqlmap tamper scripts into the correct sqlmap/tamper/ directory.
#
# Usage: ./install_tampers.sh [--backup] [--all]
#   --backup  : Back up existing files in tamper/ before overwriting.
#   --all     : Copy all .py files in the current directory (not just the 4 defaults).
#
# Author: Bearded Viking (BeardedVikingTX) | Bearded Viking Security Forge
# License: MIT (see LICENSE.md)
#===============================================================================

set -euo pipefail

# ---------- Colours for pretty output ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Colour

# ---------- Parse arguments ----------
BACKUP=false
COPY_ALL=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --backup) BACKUP=true ;;
        --all)    COPY_ALL=true ;;
        *)        echo -e "${YELLOW}Unknown option: $1${NC}"; exit 1 ;;
    esac
    shift
done

# ---------- Locate sqlmap ----------
echo -e "${GREEN}[+] Locating sqlmap installation...${NC}"

SQLMAP_CMD=$(command -v sqlmap || true)
if [ -z "$SQLMAP_CMD" ]; then
    echo -e "${RED}[!] sqlmap not found in PATH. Please ensure sqlmap is installed.${NC}"
    exit 1
fi

# Resolve symlink to get real path
SQLMAP_REAL=$(readlink -f "$SQLMAP_CMD" 2>/dev/null || echo "$SQLMAP_CMD")
SQLMAP_DIR=$(dirname "$SQLMAP_REAL")
echo -e "[+] sqlmap executable: $SQLMAP_REAL"
echo -e "[+] sqlmap directory:  $SQLMAP_DIR"

# ---------- Find tamper directory ----------
# Try: 1) sqlmap_dir/tamper (common for manual installs)
#      2) python site-packages location (pip installs)
TAMPER_DIR=""
if [ -d "$SQLMAP_DIR/tamper" ]; then
    TAMPER_DIR="$SQLMAP_DIR/tamper"
else
    # Attempt to locate via Python import
    PYTHON_SQLMAP=$(python3 -c "import sqlmap; print(sqlmap.__file__)" 2>/dev/null || true)
    if [ -n "$PYTHON_SQLMAP" ]; then
        PYTHON_SQLMAP_DIR=$(dirname "$PYTHON_SQLMAP")
        if [ -d "$PYTHON_SQLMAP_DIR/tamper" ]; then
            TAMPER_DIR="$PYTHON_SQLMAP_DIR/tamper"
        fi
    fi
fi

if [ -z "$TAMPER_DIR" ] || [ ! -d "$TAMPER_DIR" ]; then
    echo -e "${RED}[!] Could not locate sqlmap's tamper/ directory.${NC}"
    echo -e "    Tried: $SQLMAP_DIR/tamper and Python site-packages."
    echo -e "    Please specify the path manually with --tamper-path, e.g.:"
    echo -e "    ./install_tampers.sh --tamper-path /usr/share/sqlmap/tamper"
    exit 1
fi

echo -e "${GREEN}[+] Found tamper directory: $TAMPER_DIR${NC}"

# ---------- Determine which files to copy ----------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$COPY_ALL" = true ]; then
    FILES=($(ls -1 "$SCRIPT_DIR"/*.py 2>/dev/null || true))
    if [ ${#FILES[@]} -eq 0 ]; then
        echo -e "${YELLOW}[!] No .py files found in current directory.${NC}"
        exit 1
    fi
else
    # Default list of the 4 tampers
    DEFAULT_TAMPERS=(
        "random_chunk_splitter.py"
        "math_exp_obfuscator.py"
        "nested_versioned_comments.py"
        "json_unicode_escape.py"
    )
    FILES=()
    for f in "${DEFAULT_TAMPERS[@]}"; do
        if [ -f "$SCRIPT_DIR/$f" ]; then
            FILES+=("$SCRIPT_DIR/$f")
        else
            echo -e "${YELLOW}[!] Warning: $f not found in current directory. Skipping.${NC}"
        fi
    done
    if [ ${#FILES[@]} -eq 0 ]; then
        echo -e "${RED}[!] None of the default tamper scripts found. Use --all to copy everything.${NC}"
        exit 1
    fi
fi

# ---------- Perform the installation ----------
echo -e "${GREEN}[+] Copying ${#FILES[@]} tamper script(s)...${NC}"

for src in "${FILES[@]}"; do
    filename=$(basename "$src")
    dest="$TAMPER_DIR/$filename"

    # Backup existing file if requested and it exists
    if [ "$BACKUP" = true ] && [ -f "$dest" ]; then
        backup="${dest}.bak.$(date +%Y%m%d%H%M%S)"
        echo -e "${YELLOW}   [*] Backing up $filename to $backup${NC}"
        cp -p "$dest" "$backup"
    fi

    # Copy with preservation of timestamps (optional)
    cp -v "$src" "$dest" 2>&1 | sed 's/^/   /'
    # Ensure it's readable by all
    chmod 644 "$dest"
done

echo -e "${GREEN}[+] Installation complete!${NC}"
echo -e "[+] You can now use these tampers with sqlmap, e.g.:"
echo -e "    sqlmap -u 'http://target.com?id=1' --tamper=random_chunk_splitter,math_exp_obfuscator"
echo -e ""
echo -e "${YELLOW}Remember: These tools are for authorised testing only. Use responsibly.${NC}"
