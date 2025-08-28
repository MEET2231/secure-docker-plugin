#!/usr/bin/env python3
import subprocess
import json
import sys
import os
import hashlib
import shutil

# Local policy storage (per user)
POLICY_DIR = os.path.expanduser("~/.secure-docker-plugin")
POLICY_FILE = os.path.join(POLICY_DIR, "policy.json")

# Ensure policy directory exists
os.makedirs(POLICY_DIR, exist_ok=True)

def load_policy():
    """Load existing policy.json or return empty dict."""
    if os.path.exists(POLICY_FILE):
        with open(POLICY_FILE, "r") as f:
            return json.load(f)
    return {}

def save_policy(policy):
    """Save policy.json to local folder."""
    with open(POLICY_FILE, "w") as f:
        json.dump(policy, f, indent=2)
    print(f"[INFO] Policy updated: {POLICY_FILE}")

def check_image_exists(image_name):
    """Verify the image exists locally."""
    result = subprocess.run(
        ["docker", "images", "-q", image_name],
        capture_output=True, text=True
    )
    if not result.stdout.strip():
        raise RuntimeError(f"Local Docker image '{image_name}' does not exist.")

def get_layer_hashes_from_tar(image_name):
    """Compute SHA256 hashes for all layers in a Docker image."""
    # Prepare temp paths
    tar_file = f"/tmp/{image_name.replace(':','_')}.tar"
    extract_dir = f"/tmp/{image_name.replace(':','_')}_extract"

    # Cleanup old temp files if exist
    if os.path.exists(tar_file):
        os.remove(tar_file)
    if os.path.exists(extract_dir):
        shutil.rmtree(extract_dir)

    # Export image
    subprocess.run(["docker", "save", "-o", tar_file, image_name], check=True)

    # Extract tar temporarily
    os.makedirs(extract_dir, exist_ok=True)
    subprocess.run(["tar", "-xf", tar_file, "-C", extract_dir], check=True)

    # Read manifest.json
    manifest_path = os.path.join(extract_dir, "manifest.json")
    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    layer_hashes = []
    for layer_file in manifest[0]["Layers"]:
        layer_path = os.path.join(extract_dir, layer_file)
        if not os.path.exists(layer_path):
            raise RuntimeError(f"Layer file missing: {layer_path}")
        h = hashlib.sha256()
        with open(layer_path, "rb") as lf:
            while chunk := lf.read(8192):
                h.update(chunk)
        layer_hashes.append(h.hexdigest())

    # Ensure hashes are not empty
    if not layer_hashes:
        raise RuntimeError(f"No layer hashes found for image '{image_name}'.")

    # Cleanup temporary files
    shutil.rmtree(extract_dir)
    os.remove(tar_file)

    return layer_hashes

def register_image(image_name):
    """Register the image in the local policy.json."""
    check_image_exists(image_name)
    hashes = get_layer_hashes_from_tar(image_name)
    policy = load_policy()
    policy[image_name] = {"layers": hashes}
    save_policy(policy)
    print(f"[INFO] Image '{image_name}' successfully registered.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: ./register_image.py <image_name>")
        sys.exit(1)
    image_name = sys.argv[1]
    try:
        register_image(image_name)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Docker command failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Failed to register image: {e}")
        sys.exit(1)

