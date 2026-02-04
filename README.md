# DevOps Task - EC2 Access Control Sync & Repo Update

This repository contains the solution for the DevOps task to harden and automate network access to a public web server on AWS.

## Contents

- `sync_sg.py`: Python script to sync EC2 Security Group rules with Cloudflare IPs and the current Home IP.
- `security-group.yaml`: YAML template reflecting the current Security Group state.
- `requirements.txt`: Python dependencies.

## Prerequisites

- Python 3.x
- AWS Credentials configured (e.g., `~/.aws/credentials` or environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).
- Git initialized and configured.

## Usage

1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the Script:**
    ```bash
    python3 sync_sg.py
    ```

    The script will:
    - Detect your current public IP.
    - Fetch current Cloudflare IP ranges.
    - Find the EC2 instance with Public IP `34.254.140.195`.
    - Update its Security Group to allow SSH (0.0.0.0/0) and HTTP (Home IP + Cloudflare IPs).
    - Update `security-group.yaml` with the new rules.
    - Commit and push changes to the repository.

## DNS Configuration (Manual Step)

To verify access, update your local `/etc/hosts` file to point `2bcloud.io` to the specific IP `52.215.116.12`:

```bash
sudo echo "52.215.116.12 2bcloud.io" >> /etc/hosts
```

**Note:** This ensures you can reach the server via `http://2bcloud.io` from your machine.

## Verification

After running the script and updating DNS:
1.  Check the `security-group.yaml` file for updates.
2.  Test HTTP access:
    ```bash
    curl -I http://2bcloud.io
    ```
3.  Test SSH access (requires private key):
    ```bash
    ssh -i <path-to-key> credentials@2bcloud.io
    ```
