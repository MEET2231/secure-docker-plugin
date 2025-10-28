#!/usr/bin/env python3
"""
check_hash.py

Monitors Docker container creation events, verifies image integrity against the
local policy, and enforces decisions (allow/block). Supports audit logging,
colorized output, safe mode, and startup self-checks.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Optional

import docker

try:
    from colorama import Fore, Style, init as colorama_init
except Exception:  # pragma: no cover - color is optional
    Fore = type("F", (), {"RED": "", "GREEN": "", "YELLOW": ""})()
    Style = type("S", (), {"RESET_ALL": ""})()
    def colorama_init(*_, **__):  # noop if not available
        return None


POLICY_DIR = os.path.expanduser("~/.secure-docker-plugin")
POLICY_FILE = os.path.join(POLICY_DIR, "policy.json")
AUDIT_LOG = os.path.join(POLICY_DIR, "audit.log")


def cprint(prefix: str, msg: str, color: str) -> None:
    print(f"{color}{prefix}{Style.RESET_ALL} {msg}")


def log_info(msg: str) -> None:
    cprint("[INFO]", msg, Fore.GREEN)


def log_warn(msg: str) -> None:
    cprint("[WARNING]", msg, Fore.YELLOW)


def log_block(msg: str) -> None:
    cprint("[SECURITY BLOCK]", msg, Fore.RED)


def ensure_dirs():
    os.makedirs(POLICY_DIR, exist_ok=True)


def audit(event: str, container_id: str, image_name: Optional[str], message: str, digest: Optional[str] = None) -> None:
    """Append an audit event as JSONL to AUDIT_LOG."""
    ensure_dirs()
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "event": event,
        "container_id": container_id,
        "image": image_name,
        "message": message,
        "digest": digest,
    }
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except Exception as e:
        # Do not crash monitoring due to audit failures
        log_warn(f"Failed to write audit log: {e}")


def load_policy() -> dict:
    if not os.path.exists(POLICY_FILE):
        log_warn(
            f"Policy file not found at {POLICY_FILE}. Monitoring will continue, "
            "but only registered images can be verified. Run register_image.py to add images."
        )
        return {}
    try:
        with open(POLICY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log_warn(f"Failed to read policy file: {e}. Proceeding with empty policy.")
        return {}


def normalize_hashes(hashes):
    return [h.replace("sha256:", "") for h in hashes]


def get_image_digest(image: docker.models.images.Image) -> Optional[str]:
    """Extract the content digest from RepoDigests or fall back to image.id."""
    try:
        repo_digests = image.attrs.get("RepoDigests") or []
        if repo_digests:
            try:
                return repo_digests[0].split("@", 1)[1]
            except Exception:
                pass
        # Fallback to local image ID (sha256:...)
        return image.id
    except Exception:
        return None


def verify_digest(digest: Optional[str], image_name: Optional[str], policy: dict, allow_unregistered: bool) -> bool:
    """Allow if digest present in policy; otherwise block (unless allowed by flag)."""
    if digest and digest in policy:
        return True
    if allow_unregistered:
        log_info(
            f"Image '{image_name}' (digest {digest}) not registered. Allowed due to --allow-unregistered."
        )
        return True
    log_block(f"Image '{image_name}' (digest {digest}) is not registered in policy.")
    return False


def check_permissions():
    if not os.path.exists(POLICY_FILE):
        return
    try:
        st = os.stat(POLICY_FILE)
        insecure = bool(st.st_mode & 0o022)  # group/other writable
        if insecure:
            log_warn(
                f"Policy file permissions are too open ({oct(st.st_mode & 0o777)}). "
                "Recommended 600 (chmod 600)."
            )
    except Exception as e:
        log_warn(f"Could not check policy file permissions: {e}")


def self_check(client: docker.DockerClient) -> bool:
    """Validate environment: Docker daemon reachable, policy dir present, perms."""
    # Docker daemon
    try:
        client.ping()
    except Exception as e:
        cprint("[ERROR]", f"Docker daemon is not reachable: {e}", Fore.RED)
        return False

    # Ensure dirs and check policy file permissions
    ensure_dirs()
    check_permissions()
    return True


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Monitor Docker create events and verify image layer hashes against the local policy.\n"
            "Use --safe-mode to stop (not remove) containers on violations."
        )
    )
    parser.add_argument(
        "--safe-mode",
        action="store_true",
        help="Safer enforcement: stop containers instead of removing on block",
    )
    parser.add_argument(
        "--allow-unregistered",
        action="store_true",
        help="Compatibility mode: allow containers from images not present in the policy",
    )
    return parser.parse_args()


def main():
    colorama_init(autoreset=True)
    args = parse_args()

    client = docker.from_env()
    if not self_check(client):
        sys.exit(1)

    policy = load_policy()
    if not policy and not args.allow_unregistered:
        log_warn(
            "Policy is empty and strict mode is active: all images will be blocked until you register some with register_image.py"
        )
    log_info("Monitoring Docker container creation events… (Ctrl+C to exit)")
    if args.safe_mode:
        log_info("Safe mode enabled: will stop, not remove, blocked containers")
    if args.allow_unregistered:
        log_warn("--allow-unregistered enabled: unregistered images will be allowed")

    # Track decision per container to reduce duplicate audits and re-enforce if needed
    decisions = {}  # type: dict[str, bool]

    def enforce_block(container: docker.models.containers.Container, container_id: str) -> None:
        try:
            # Refresh state
            try:
                container.reload()
            except Exception:
                pass
            running = False
            try:
                running = bool(container.attrs.get("State", {}).get("Running", False))
            except Exception:
                pass

            if running:
                action = "Stopping" if args.safe_mode else "Stopping and removing"
                log_block(f"{action} container {container_id}")
                container.stop()
                if not args.safe_mode:
                    container.remove()
            else:
                if args.safe_mode:
                    # Not running; stopping would be a no-op. Leave it for inspection.
                    log_block(f"Container {container_id} blocked (not running). Left in place due to safe mode.")
                else:
                    log_block(f"Removing blocked container {container_id}")
                    container.remove()
        except docker.errors.NotFound:
            # Already gone
            log_info(f"Container {container_id} already removed.")
        except Exception as e:
            log_warn(f"Failed to enforce block on {container_id}: {e}")

    try:
        for event in client.events(decode=True):
            try:
                if event.get("Type") == "container" and event.get("Action") in ("create", "start"):
                    container_id = event.get("id", "<unknown>")
                    try:
                        container = client.containers.get(container_id)
                    except Exception as e:
                        log_warn(f"Could not get container {container_id}: {e}")
                        continue
                    image_name = container.image.tags[0] if container.image.tags else None
                    image = container.image
                    digest = get_image_digest(image)

                    if event.get("Action") == "create":
                        audit("CREATED", container_id, image_name, "Container created", digest)
                        if not image_name:
                            log_warn(f"Container {container_id} has no tagged image. Proceeding with digest-based check.")

                        log_info(f"Container {container_id} created using image '{image_name}' (digest {digest})")

                        if container_id not in decisions:
                            allowed = verify_digest(digest, image_name, policy, args.allow_unregistered)
                            decisions[container_id] = allowed
                            if allowed:
                                audit("ALLOWED", container_id, image_name, "Digest registered or allowed by flag", digest)
                            else:
                                audit("BLOCKED", container_id, image_name, "Digest not registered", digest)
                                enforce_block(container, container_id)
                        else:
                            if decisions.get(container_id) is False:
                                enforce_block(container, container_id)

                    elif event.get("Action") == "start":
                        if container_id not in decisions:
                            if not image_name and not digest:
                                log_warn(f"Container {container_id} has no image metadata on start. Blocking by default.")
                                decisions[container_id] = False
                                audit("BLOCKED", container_id, image_name, "No image metadata; blocked on start", digest)
                                enforce_block(container, container_id)
                                continue
                            allowed = verify_digest(digest, image_name, policy, args.allow_unregistered)
                            decisions[container_id] = allowed
                            if allowed:
                                audit("ALLOWED", container_id, image_name, "Digest registered or allowed by flag", digest)
                            else:
                                audit("BLOCKED", container_id, image_name, "Digest not registered", digest)
                                enforce_block(container, container_id)
                        else:
                            if decisions.get(container_id) is False:
                                enforce_block(container, container_id)
            except Exception as e:
                log_warn(f"Error handling event: {e}")

    except KeyboardInterrupt:
        print()
        log_info("Exiting monitoring.")
        sys.exit(0)


if __name__ == "__main__":
    main()

