#!/usr/bin/env python3
import docker
import json
import os
import sys

POLICY_FILE = os.path.expanduser("~/.secure-docker-plugin/policy.json")

def load_policy():
    if not os.path.exists(POLICY_FILE):
        print(f"[ERROR] Policy file not found: {POLICY_FILE}")
        return {}
    with open(POLICY_FILE, "r") as f:
        return json.load(f)

def normalize_hashes(hashes):
    return [h.replace("sha256:", "") for h in hashes]

def verify_image(image_name, policy):
    if image_name not in policy:
        print(f"[INFO] Image '{image_name}' not registered. Skipping check.")
        return True

    client = docker.from_env()
    image = client.images.get(image_name)
    runtime_hashes = normalize_hashes(image.attrs['RootFS']['Layers'])
    registered_hashes = normalize_hashes(policy[image_name]['layers'])

    if runtime_hashes != registered_hashes:
        print(f"[SECURITY BLOCK] Image '{image_name}' layer hashes mismatch!")
        return False
    return True

def main():
    client = docker.from_env()
    policy = load_policy()
    print("[INFO] Monitoring Docker container creation events...")

    try:
        for event in client.events(decode=True):
            if event['Type'] == 'container' and event['Action'] == 'create':
                container_id = event['id']
                container = client.containers.get(container_id)
                image_name = container.image.tags[0] if container.image.tags else None

                if not image_name:
                    print(f"[WARNING] Container {container_id} has no tagged image. Skipping.")
                    continue

                print(f"[INFO] Container {container_id} created using image '{image_name}'")
                allowed = verify_image(image_name, policy)

                if not allowed:
                    print(f"[INFO] Stopping and removing container {container_id}")
                    container.stop()
                    container.remove()

    except KeyboardInterrupt:
        print("\n[INFO] Exiting monitoring.")
        sys.exit(0)

if __name__ == "__main__":
    main()

