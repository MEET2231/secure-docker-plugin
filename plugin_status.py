#!/usr/bin/env python3
"""
plugin_status.py

Shows a summary dashboard for the Secure Docker Plugin:
- Number of images registered in the policy
- Total blocked and allowed containers from the audit log
- Last 5 security events
"""
import json
import os
from datetime import datetime
from typing import List, Dict

try:
    from colorama import Fore, Style, init as colorama_init
except Exception:  # pragma: no cover - color is optional
    Fore = type("F", (), {"RED": "", "GREEN": "", "YELLOW": "", "CYAN": ""})()
    Style = type("S", (), {"RESET_ALL": ""})()
    def colorama_init(*_, **__):
        return None

POLICY_DIR = os.path.expanduser("~/.secure-docker-plugin")
POLICY_FILE = os.path.join(POLICY_DIR, "policy.json")
AUDIT_LOG = os.path.join(POLICY_DIR, "audit.log")


def load_policy() -> dict:
    if not os.path.exists(POLICY_FILE):
        return {}
    try:
        with open(POLICY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def load_audit() -> List[Dict]:
    events: List[Dict] = []
    if not os.path.exists(AUDIT_LOG):
        return events
    try:
        with open(AUDIT_LOG, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except Exception:
                    # skip malformed entries
                    continue
    except Exception:
        pass
    return events


def parse_time(ts: str) -> datetime:
    try:
        if ts.endswith("Z"):
            ts = ts[:-1]
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.min


def main():
    colorama_init(autoreset=True)

    policy = load_policy()
    events = load_audit()

    # Estimate unique registered images by digest; fall back to keys if missing
    digests = set()
    for k, v in policy.items():
        d = v.get("digest") if isinstance(v, dict) else None
        if d:
            digests.add(d)
        else:
            if isinstance(k, str) and k.startswith("sha256:"):
                digests.add(k)
            else:
                digests.add(k)
    total_images = len(digests)
    allowed = sum(1 for e in events if e.get("event") == "ALLOWED")
    blocked = sum(1 for e in events if e.get("event") == "BLOCKED")

    last_events = sorted(events, key=lambda e: parse_time(e.get("timestamp", "")), reverse=True)[:5]

    # Header
    print(f"{Fore.CYAN}== Secure Docker Plugin Status =={Style.RESET_ALL}")

    # Summary
    print(f"{Fore.GREEN}Registered images:{Style.RESET_ALL} {total_images}")
    print(f"{Fore.GREEN}Allowed containers:{Style.RESET_ALL} {allowed}")
    print(f"{Fore.RED}Blocked containers:{Style.RESET_ALL} {blocked}")

    # Recent events
    print()
    print(f"{Fore.CYAN}Last 5 events:{Style.RESET_ALL}")
    if not last_events:
        print("(no events yet)")
    else:
        for e in last_events:
            ts = e.get("timestamp", "?")
            ev = e.get("event", "?")
            cid = e.get("container_id", "?")
            img = e.get("image", "?")
            msg = e.get("message", "")
            color = Fore.GREEN if ev == "ALLOWED" else (Fore.RED if ev == "BLOCKED" else Fore.YELLOW)
            print(f"{color}{ts}{Style.RESET_ALL} {ev:<7} {cid} {img} - {msg}")


if __name__ == "__main__":
    main()
