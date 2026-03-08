#!/usr/bin/env bash
# install.sh — vorteX installation helper
#
# Detects if pipx is available and uses it; otherwise creates a virtual
# environment and installs there. Works on Kali, Parrot, Ubuntu, and macOS.
#
# Usage:
#   bash install.sh
#   bash install.sh --dev        # install in editable/dev mode

set -euo pipefail

VENV_DIR=".venv"
MODE="${1:-}"

echo "================================================================"
echo "  vorteX — Installation Helper"
echo "================================================================"
echo ""

# ── Helper functions ────────────────────────────────────────────────

command_exists() {
    command -v "$1" > /dev/null 2>&1
}

print_ok()  { echo "[✔] $*"; }
print_info(){ echo "[*] $*"; }
print_warn(){ echo "[!] $*"; }

# ── Check Python version ────────────────────────────────────────────

if ! command_exists python3; then
    print_warn "python3 not found. Please install Python 3.9+."
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
print_info "Python version: $PY_VERSION"

REQUIRED_MAJOR=3
REQUIRED_MINOR=9
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -lt "$REQUIRED_MAJOR" ] || { [ "$PY_MAJOR" -eq "$REQUIRED_MAJOR" ] && [ "$PY_MINOR" -lt "$REQUIRED_MINOR" ]; }; then
    print_warn "Python $REQUIRED_MAJOR.$REQUIRED_MINOR+ is required (found $PY_VERSION)."
    exit 1
fi

# ── Dev mode ────────────────────────────────────────────────────────

if [ "$MODE" = "--dev" ]; then
    print_info "Dev mode: creating virtual environment at $VENV_DIR/ ..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip --quiet
    "$VENV_DIR/bin/pip" install -e ".[dev]" --quiet
    print_ok "Dev environment installed at $VENV_DIR/"
    echo ""
    echo "  Activate with:  source $VENV_DIR/bin/activate"
    echo "  Run linter:     ruff check vortex/ tests/"
    echo "  Run tests:      pytest tests/ -v"
    echo ""
    exit 0
fi

# ── Standard install: try pipx first ────────────────────────────────

if command_exists pipx; then
    print_info "pipx detected — using pipx for isolated install..."
    pipx install .
    print_ok "vorteX installed via pipx."
    echo ""
    echo "  Run with:  vorteX -h"
    echo ""
    exit 0
fi

# ── Fallback: venv install ───────────────────────────────────────────

print_info "pipx not found — creating virtual environment at $VENV_DIR/ ..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip --quiet
"$VENV_DIR/bin/pip" install . --quiet

print_ok "vorteX installed in $VENV_DIR/"
echo ""
echo "  Activate the environment:"
echo "    source $VENV_DIR/bin/activate"
echo ""
echo "  Or create a symlink so you can run 'vorteX' globally:"
echo "    sudo ln -sf \$(pwd)/$VENV_DIR/bin/vorteX /usr/local/bin/vorteX"
echo ""
echo "  Then run:  vorteX -h"
echo ""
echo "  NOTE: On PEP 668 systems (Kali, Parrot, Ubuntu 23+) bare"
echo "  'pip install .' will fail. Use this script or 'make install'"
echo "  instead — do NOT use --break-system-packages."
echo ""
