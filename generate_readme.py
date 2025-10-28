#!/usr/bin/env python3
"""
generate_readme.py

Generates a README.md based on script docstrings and usage information.
This is a convenience tool to keep documentation up to date and user-friendly.
"""
import ast
import os
from textwrap import dedent
from typing import Optional

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
TARGET = os.path.join(REPO_ROOT, "README.md")

SCRIPTS = [
    ("register_image.py", "Register Docker images by computing and storing layer hashes."),
    ("check_hash.py", "Monitor Docker create events and verify images against policy."),
    ("plugin_status.py", "Show summary statistics and last security events."),
]


def get_docstring(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=path)
        return ast.get_docstring(tree)
    except Exception:
        return None


def main():
    parts = []
    parts.append("# Secure Docker Plugin\n")
    parts.append(
        dedent(
            """
            A lightweight, user-space security helper for Docker that verifies container image integrity by tracking layer hashes.
            
            ## 🔑 Key Features
            
            - Image integrity verification using SHA256 layer hashes
            - Real-time container monitoring and policy enforcement
            - Audit logging with detailed event tracking
            - Colorized output for better visibility
            - Safe mode for testing and demonstration
            - Status dashboard with security insights
            
            ## 📋 Requirements
            
            - Python 3.9+
            - Docker
            - pip (Python package installer)
            
            ## 🚀 Quick Start
            
            1. Run setup:
               ```bash
               ./setup.sh
               ```
            2. Register an image:
               ```bash
               ./register_image.py <image_name>
               ```
            3. Start monitoring:
               ```bash
               ./check_hash.py [--safe-mode]
               ```
            4. View status:
               ```bash
               ./plugin_status.py
               ```
            
            ## 🛠️ Components
            """
        )
    )

    for fname, fallback in SCRIPTS:
        path = os.path.join(REPO_ROOT, fname)
        title = os.path.splitext(fname)[0]
        doc = get_docstring(path) or fallback
        parts.append(f"### 🔹 {fname}\n\n{doc}\n\n")
        # Basic usage hints
        if fname == "register_image.py":
            parts.append(dedent(
                """
                Usage:

                ```bash
                ./register_image.py <image_name>
                ```
                
                """
            ))
        elif fname == "check_hash.py":
            parts.append(dedent(
                """
                Usage:

                ```bash
                ./check_hash.py [--safe-mode]
                ```
                
                """
            ))
        elif fname == "plugin_status.py":
            parts.append(dedent(
                """
                Usage:

                ```bash
                ./plugin_status.py
                ```
                
                """
            ))

    parts.append(
        dedent(
            """
            ## 📝 Audit Logging
            
            Events are logged to `~/.secure-docker-plugin/audit.log` as JSON lines with:
            - timestamp
            - event (CREATED/ALLOWED/BLOCKED)
            - container_id
            - image
            - message
            
            ## 🔒 Security Policy
            
            The policy file is at `~/.secure-docker-plugin/policy.json` and contains registered image layer hashes.
            
            ## 📜 License
            
            MIT
            """
        )
    )

    with open(TARGET, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))

    print(f"[INFO] README generated at {TARGET}")


if __name__ == "__main__":
    main()
