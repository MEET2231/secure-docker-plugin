# Secure Docker Plugin — Presentation Summary

A lightweight, user-space security helper that enforces which container images may run on a host, with digest-based policy, audit logging, safe mode, and a small dashboard.

## What problem it solves
- Tags (like `alpine:latest`) can change and are not trustworthy for allowlists.
- We enforce by image digest (immutable content fingerprint) so only exactly-registered images can run.

## Architecture at a glance
- Policy file: `~/.secure-docker-plugin/policy.json` (per user)
- Monitor: `check_hash.py` listens to Docker events and enforces policy
- Registration: `register_image.py` stores approved image digests (and layer info)
- Audit: JSON-lines at `~/.secure-docker-plugin/audit.log`
- Dashboard: `plugin_status.py` shows totals and recent events

## Core concepts
- Image digest
  - A SHA-256 fingerprint of image content (e.g., `sha256:abcd…`).
  - Prefer registry `RepoDigest` (manifest digest); fallback to local `image.id` if missing.
  - Digest is immutable: same digest = same content.
- Policy
  - A set of allowed digests saved in `policy.json` by `register_image.py`.
  - Each entry contains: `digest`, `layers` (provenance/debug), and a reference to the tag.
  - The monitor allows a container only if its digest is present in the policy (strict by default).
- Enforcement modes
  - Strict (default): block any container whose digest is not in the policy.
  - Compatibility: `--allow-unregistered` flag allows unregistered images (useful for testing).
- Safe mode
  - `--safe-mode`: on a block, stop the container but do not remove it (safer demo).
  - Without safe mode: stop and remove blocked containers.
- Audit logging
  - Every event written as JSONL: `timestamp`, `event` (CREATED|ALLOWED|BLOCKED), `container_id`, `image`, `digest`, `message`.
  - Location: `~/.secure-docker-plugin/audit.log`.
- Self-check
  - On startup: ensures Docker is reachable, policy dir exists, and warns on loose policy permissions.

## Setup (one-time)
```bash
./setup.sh
```
If Docker requires sudo or group membership, follow your distro’s guidance (e.g., `sudo usermod -aG docker $USER && newgrp docker`).

## Typical flow (demo-ready)
1) Pull and register images you want to allow
```bash
docker pull alpine:latest
./register_image.py alpine:latest
```
2) Start the monitor
```bash
# Safer for demos
./check_hash.py --safe-mode
```
3) Run a container
```bash
docker run --rm -d --name demo alpine:latest sleep 60
```
4) See status
```bash
./plugin_status.py
```

## What you’ll see during a demo
- When a container is created, the monitor logs CREATED with the image digest.
- If the digest is in policy → ALLOWED.
- If not in policy → BLOCKED (stopped in safe mode; stopped+removed otherwise).
- Dashboard shows total registered images, counts of allowed/blocked, and last 5 events.

## Security posture and limits
- Strong allowlist semantics by immutable digest; tags alone are not trusted.
- User-space only (no kernel mods). Uses standard Docker SDK and events.
- If policy is empty in strict mode, everything will be blocked until images are registered.
- Locally built images without RepoDigests use `image.id` (still a sha256 content ID, but local).

## File map (for the talk)
- `register_image.py` — compute layer hashes, resolve digest, save to `policy.json` (both tag and digest keys).
- `check_hash.py` — monitor Docker events, enforce by digest, audit logs, safe mode, self-checks.
- `plugin_status.py` — quick dashboard from policy and audit log.
- `generate_readme.py` — builds README.md from docstrings.
- `setup.sh` — installs deps and sets exec bits.

## Handy commands (copy/paste)
- Install and prepare:
```bash
./setup.sh
```
- Register allowed image:
```bash
./register_image.py alpine:latest
```
- Start monitor (strict + safe):
```bash
./check_hash.py --safe-mode
```
- Run a container (should be allowed if registered):
```bash
docker run --rm -d --name demo alpine:latest sleep 60
```
- Show dashboard:
```bash
./plugin_status.py
```
- View audit log:
```bash
tail -n 20 ~/.secure-docker-plugin/audit.log
```

## FAQ quickies
- Why digest and not tag? Tags move; digest is immutable and trustworthy.
- Why record layers if we enforce by digest? Useful for audits and future policy rules.
- Can I allow unregistered images? Only with `--allow-unregistered` (not recommended for prod).
