
# Secure Docker Plugin

This project demonstrates a **runtime Docker image verification system**. It monitors Docker container creation and ensures that only images with registered, unmodified layers are allowed to run.

## Features

- **Register Docker images**: Store the trusted layer hashes locally.
- **Runtime verification**: Monitor Docker container creation events and block containers if the image has been tampered with.
- **Local policy storage**: Registered images are stored in a user-specific folder (`~/.secure-docker-plugin/policy.json`).
- **Automatic stop & removal**: Containers using tampered images are immediately stopped and removed.

---

## Requirements

- Docker installed and running
- Python 3.12+
- Python dependencies: `docker` (`pip install docker`)

---

## Setup & Usage

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd secure-docker-plugin
```


All scripts (`register_image.py`, `check_hash.py`) are in this folder.



### 2. Build your Docker image

```bash
cd /path/to/your/application
docker build -t pythonapp:latest .

```

-   Replace `/path/to/your/application` with your folder containing the Dockerfile and application files.
    
-   Ensure the build completes successfully.
    

----------

### 3. Register the image

```bash
cd /path/to/secure-docker-plugin
./register_image.py pythonapp:latest

```

-   Extracts the layer hashes and stores them in the local policy file:  
    `~/.secure-docker-plugin/policy.json`
    
-   The image must exist locally before registration.
    

----------

### 4. Run the runtime monitor

```bash
cd /path/to/secure-docker-plugin
./check_hash.py

```

-   Continuously monitors Docker events.
    
-   **Behavior:** Containers created from tampered images are **stopped and removed immediately**.
    

Example terminal output:

```
[INFO] Container <container_id> created using image 'pythonapp:latest'
[SECURITY BLOCK] Image 'pythonapp:latest' layer hashes mismatch!
[INFO] Stopping and removing container <container_id>

```

----------

### 5. Verify blocked containers

-   To see all containers (running or exited):
    

```bash
docker ps -a

```

-   Tampered containers may appear as **Exited** or may not appear at all, depending on timing.
    

----------

### 6. Example: Tampering with an image

1.  **Modify the Dockerfile or source code** of a previously registered image.  
    For example, add a comment, change a line, or modify `app.py`.
    

```dockerfile
# Original Dockerfile
FROM python:3.11-slim
WORKDIR /myapp
COPY . /myapp
CMD ["python", "app.py"]

```

```dockerfile
# Tampered Dockerfile (added comment)
FROM python:3.11-slim
WORKDIR /myapp
COPY . /myapp
RUN echo "tamper test" >> /myapp/tamper.txt
CMD ["python", "app.py"]

```

2.  **Rebuild the image** with the same tag (or a new tag):
    

```bash
docker build -t pythonapp:latest .

```

3.  **Try to run a container**:
    

```bash
docker run -d --name test_tampered pythonapp:latest

```

-   The monitor (`check_hash.py`) should detect that the image's **layer hashes do not match the registered policy** and immediately stop & remove the container.
    

----------

### Notes

-   The monitor reacts **after container creation**, so Docker initially assigns a container ID. It is removed immediately if the image is tampered.
    
-   Policy file is user-specific and stored locally (`~/.secure-docker-plugin/policy.json`). It does **not sync between machines**.
    
-   To completely avoid initial container IDs, a **pre-run wrapper** would be needed (not implemented yet).
    



