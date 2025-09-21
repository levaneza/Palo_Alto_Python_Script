# PAN-OS Automation Script
This project provides a Python-based command-line tool to manage Palo Alto Networks (PAN-OS) firewall configurations using its XML API. It is designed to be 
lightweight, with `PyYAML` as its only external dependency.
The script reads its configuration from a file, allowing you to define devices, objects (tags, addresses, services), and security policies in a structured, 
version-controllable format. `inventory.yml`
## Features
- **Declarative Configuration**: Define your desired state in a file. `inventory.yml`
- **Apply Configuration**: Create or update all objects and policies from the inventory on the firewall.
- **Delete Operations**:
    - Delete a single object or policy by name.
    - Delete all items defined in the inventory in a dependency-safe order.

- **Health Check**: A simple command to test API connectivity and authentication.
- **Idempotent-Aware Logic**: Includes checks for existing zones and log forwarding profiles to avoid common errors.
- **No External Libraries (besides PyYAML)**: Uses only Python's standard library for API communication.
- **Secure**: Reads the sensitive API key from an environment variable () to avoid storing it in files. `PA_API_KEY`

## Requirements
- Python 3.9+
- for installing dependencies. `pip`
- A Palo Alto Networks firewall with API access enabled on its management interface.
- An admin role or an API service account with permissions to create/delete objects and policies, and to commit changes.

## 1. Setup and Installation
Follow these steps to set up your environment.
#### a. Create a Virtual Environment
It is highly recommended to use a virtual environment to manage dependencies.
**macOS / Linux:**
``` bash
python3 -m venv .venv
source .venv/bin/activate
```
**Windows (PowerShell):**
``` powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
#### b. Install Dependencies
The only required package is `PyYAML`. First, ensure your file contains only the following line: `requirements.txt`
``` 
PyYAML>=6.0
```
Then, install it:
``` bash
# Upgrade pip (recommended)
python -m pip install --upgrade pip

# Install from requirements.txt
pip install -r requirements.txt
```
#### c. Set Environment Variable
The script requires the PAN-OS API key to be set as an environment variable named . `PA_API_KEY`
**macOS / Linux:**
``` bash
export PA_API_KEY='YOUR_API_KEY_HERE'
```
**Windows (PowerShell):**
``` powershell
$env:PA_API_KEY = 'YOUR_API_KEY_HERE'
```
**To generate an API key**, you can use this `curl` command or do it via the firewall's web interface:
``` bash
curl -k -X GET "https://<firewall-ip>/api/?type=keygen&user=<username>&password=<password>"
```
## 2. File Structure
- **`main.py`**: The main script containing all the logic for API communication and configuration management.
- **`inventory.yml`**: The YAML file where you define your firewall devices, objects, and policies. **This is the file you will edit the most.**
- **`requirements.txt`**: Lists the Python dependencies needed for the project.

## 3. Inventory File () `inventory.yml`
This file is the source of truth for the script. It is structured into three main sections: , , and . `devices``objects``policies`
``` yaml
# inventory.yml
devices:
  - name: pa-fw-1             # A friendly name for the device
    host: 172.24.24.1        # IP address or FQDN of the firewall
    vsys: vsys1              # Target virtual system (default: vsys1)
    verify_ssl: false        # Set to true if using a trusted certificate

objects:
  tags:
    - name: Prod
      color: 5                 # PAN-OS color ID (e.g., 1-17)
      comments: Production
    - name: Web                # A tag with no color or comments

  addresses:
    - name: web-srv-1
      type: ip-netmask         # Can be ip-netmask, ip-range, or fqdn
      value: 203.0.113.10
      description: Web server 1
      tags: [Prod, Web]

  address_groups:
    - name: web-servers
      static_members: [web-srv-1]
      description: All web servers
      tags: [Prod, Web]

  services:
    - name: svc-https
      protocol: tcp            # tcp or udp
      ports: "443"             # e.g., "80,443", "1024-2000"
      description: HTTPS
      tags: [Web]

  service_groups:
    - name: web-services
      members: [svc-https]

policies:
  security:
    - name: allow-prod-web-out
      description: Allow outbound web from Prod servers
      from_zones: [Trust]
      to_zones: [Untrust]
      source_addresses: [web-servers]
      destination_addresses: [any]
      applications: [ssl, web-browsing]
      services: [application-default] # or a service/service-group name
      users: [any]
      tags: [Prod]
      action: allow
      log_setting: default # Optional: Name of a log forwarding profile
      log_start: false
      log_end: true
      disabled: false
```
## 4. Usage
All commands are run from your terminal with the virtual environment activated and set. `PA_API_KEY`
#### Health Check
Test API connectivity to the device specified in your inventory.
``` bash
python3 main.py health --inventory inventory.yml
```
**Success:** **Failure:** An error message explaining the connectivity issue. `[health] success: API reachable and authenticated.`
#### Apply Configuration
Create all objects and policies defined in on the firewall. `inventory.yml`
``` bash
# Apply and commit
python3 main.py apply --inventory inventory.yml

# Apply with detailed progress (recommended)
python3 main.py apply --inventory inventory.yml --verbose

# Apply without committing the changes (a "dry run" for the candidate config)
python3 main.py apply --inventory inventory.yml --no-commit
```
#### Delete a Single Item
Delete a specific object or policy by its kind and name.
``` bash
# Delete a security rule
python3 main.py delete --inventory inventory.yml --kind security-rule --name allow-prod-web-out

# Delete an address object
python3 main.py delete --inventory inventory.yml --kind address --name web-srv-1
```
Note: Deletion will fail if the object is still referenced by another rule or object. You must delete dependents first.#### Delete All from Inventory
Delete all items defined in . The script performs this in a dependency-safe order to minimize errors. `inventory.yml`
``` bash
# Delete all items and commit
python3 main.py delete-all --inventory inventory.yml

# Fail immediately if any single deletion fails
python3 main.py delete-all --inventory inventory.yml --strict
```
## 5. Troubleshooting
- **No output when running a command**:
    1. Ensure your virtual environment is active (`source .venv/bin/activate`).
    2. Verify the environment variable is set (`echo $PA_API_KEY`). `PA_API_KEY`
    3. Check that the file paths for and are correct. `main.py``inventory.yml`
    4. Run with the and flags for maximum output. `--verbose``--debug`

- **`Malformed Request` Error**: This usually means the XML payload sent to the firewall was invalid. Check your for syntax errors or unsupported fields. 
`inventory.yml`
- **"Cannot be deleted because of references"**: You are trying to delete an object (e.g., an address group) that is currently used in a policy. Delete the policy 
first, then the object. The command handles this automatically. `delete-all`
- **SSL Errors**: If your firewall uses a self-signed certificate, ensure is set in your or do not use the command-line flag. `verify_ssl: 
false``inventory.yml``--verify-ssl`

## 6. Security
- **API Key**: Treat the as a password. Do not hardcode it into scripts or commit it to version control. Using an environment variable is the recommended approach. 
`PA_API_KEY`
- **Permissions**: For production use, create a dedicated API service account with the minimum required permissions instead of using a superuser admin account.

