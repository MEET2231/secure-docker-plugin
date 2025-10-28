#!/usr/bin/env bash
set -e

# Install Python dependencies (user-local)
python3 -m pip install --user --upgrade pip >/dev/null 2>&1 || true
python3 -m pip install --user docker colorama

# Ensure scripts are executable
chmod +x check_hash.py register_image.py plugin_status.py generate_readme.py || true
chmod +x run.sh || true

# Ensure plugin data directory exists
mkdir -p "$HOME/.secure-docker-plugin"

echo "Setup complete. Try:"
echo "  ./register_image.py <image_name>"
echo "  ./check_hash.py --safe-mode"
echo "  ./plugin_status.py"