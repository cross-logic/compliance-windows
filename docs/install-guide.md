# Installation Guide

This guide covers installing the `security.compliance_windows` compliance profile on AAP Controller, including prerequisites, installation steps, credential configuration, verification, and uninstallation.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation Overview](#installation-overview)
- [Step 1: Verify Prerequisites](#step-1-verify-prerequisites)
- [Step 2: Configure WinRM Credentials](#step-2-configure-winrm-credentials)
- [Step 3: Run install.yml](#step-3-run-installyml)
- [Step 4: Verify Installation](#step-4-verify-installation)
- [What install.yml Creates](#what-installyml-creates)
- [Post-Installation Configuration](#post-installation-configuration)
- [Uninstallation](#uninstallation)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Before installing the Windows Server STIG compliance profile, ensure the following resources exist on AAP Controller:

### 1. AAP Controller

- AAP 2.5 or later
- Organization: `Default` (or custom org)
- API access token with admin permissions

### 2. Execution Environment

Build or import the Windows compliance EE:

```bash
# Pull from PAH
podman pull aap-netrunner.demoredhat.com/compliance-windows-stig:latest

# Or build locally
cd ee/stig
ansible-builder build -f execution-environment.yml -t compliance-windows-stig:latest
podman push compliance-windows-stig:latest aap-netrunner.demoredhat.com/compliance-windows-stig:latest
```

Register the EE in Controller:
- **Name**: `compliance-windows-stig`
- **Image**: `aap-netrunner.demoredhat.com/compliance-windows-stig:latest`
- **Pull**: `Always` (or `If not present` for air-gapped)

### 3. Inventory

Create an inventory with Windows Server targets:

```yaml
# inventory.yml
all:
  children:
    windows:
      hosts:
        win-server-01:
          ansible_host: 192.168.1.101
        win-server-02:
          ansible_host: 192.168.1.102
  vars:
    ansible_connection: winrm
    ansible_winrm_transport: credssp
    ansible_winrm_server_cert_validation: ignore
    ansible_port: 5986
```

Import to Controller:
- **Name**: `compliance-windows-inventory`
- **Type**: `Inventory`
- Add hosts via GUI or sync from SCM

### 4. WinRM Credential

Create a Machine Credential with administrator access:
- **Name**: `windows-admin`
- **Type**: `Machine`
- **Username**: `DOMAIN\Administrator` (or local `Administrator`)
- **Password**: (set securely)

See [Step 2: Configure WinRM Credentials](#step-2-configure-winrm-credentials) for detailed setup.

### 5. Project

Create a Project pointing to the collection:

```yaml
# Option A: Git SCM
Name: compliance-profile-windows
SCM Type: Git
SCM URL: https://github.com/stevefulme1/compliance-windows.git
SCM Branch: main

# Option B: Manual (for local development)
Name: compliance-profile-windows
SCM Type: Manual
Playbook Directory: /var/lib/awx/projects/compliance-windows
```

## Installation Overview

The `install.yml` playbook:
1. Creates an assessment job template (DISA STIG scan)
2. Creates a remediation job template (apply STIG controls)
3. Registers profile metadata in Controller extra_vars
4. (Optional) Reconnects profile in Ansible Portal compliance backend

Installation takes ~2 minutes and requires no target host access.

## Step 1: Verify Prerequisites

Check that all prerequisites exist:

```bash
# Login to Controller
export AAP_HOST=https://controller.example.com
export AAP_API_TOKEN=<your-token>

# Verify EE exists
curl -s -k -H "Authorization: Bearer $AAP_API_TOKEN" \
  $AAP_HOST/api/v2/execution_environments/ | jq '.results[] | select(.name == "compliance-windows-stig")'

# Verify inventory exists
curl -s -k -H "Authorization: Bearer $AAP_API_TOKEN" \
  $AAP_HOST/api/v2/inventories/ | jq '.results[] | select(.name == "compliance-windows-inventory")'

# Verify project exists
curl -s -k -H "Authorization: Bearer $AAP_API_TOKEN" \
  $AAP_HOST/api/v2/projects/ | jq '.results[] | select(.name == "compliance-profile-windows")'

# Verify credential exists
curl -s -k -H "Authorization: Bearer $AAP_API_TOKEN" \
  $AAP_HOST/api/v2/credentials/ | jq '.results[] | select(.name == "windows-admin")'
```

## Step 2: Configure WinRM Credentials

### Enable WinRM on Windows Targets

On each Windows Server target, enable WinRM and configure CredSSP:

```powershell
# Enable WinRM
Enable-PSRemoting -Force

# Configure CredSSP authentication
Enable-WSManCredSSP -Role Server -Force

# Allow HTTPS on port 5986
New-NetFirewallRule -Name "WinRM HTTPS" -DisplayName "WinRM HTTPS" -Enabled True -Direction Inbound -Protocol TCP -LocalPort 5986

# Create self-signed certificate (or use domain cert)
$cert = New-SelfSignedCertificate -DnsName "win-server-01.example.com" -CertStoreLocation Cert:\LocalMachine\My
New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbprint $cert.Thumbprint -Force
```

### Configure Ansible Controller Credential

Create a Machine Credential in Controller:

1. Navigate to **Resources > Credentials**
2. Click **Add**
3. Fill in:
   - **Name**: `windows-admin`
   - **Credential Type**: `Machine`
   - **Username**: `DOMAIN\Administrator` (or `Administrator` for local)
   - **Password**: (enter password)
4. Click **Save**

### Test WinRM Connectivity

Create a test job template:

```yaml
# test-winrm.yml
---
- name: Test WinRM connectivity
  hosts: windows
  gather_facts: false
  tasks:
    - name: Ping Windows host
      ansible.windows.win_ping:
```

Run the test JT to verify connectivity.

## Step 3: Run install.yml

Install the profile via the playbook:

```bash
# Set environment variables
export AAP_HOST=https://controller.example.com
export AAP_API_TOKEN=<your-token>

# Optional: set Backstage API URL for backend registration
export BACKSTAGE_API_URL=https://portal.example.com
export BACKSTAGE_TOKEN=<backstage-token>

# Run install playbook
ansible-playbook install.yml
```

Alternatively, pass values via `-e`:

```bash
ansible-playbook install.yml \
  -e aap_host=https://controller.example.com \
  -e aap_token=<your-token> \
  -e organization=Default \
  -e project=compliance-profile-windows \
  -e inventory=compliance-windows-inventory \
  -e execution_environment=compliance-windows-stig
```

### Installation Output

```
PLAY [Install: DISA STIG Windows Server Profile] *******************************

TASK [Validate required variables] *********************************************
ok: [localhost]

TASK [Create assessment job template] ******************************************
changed: [localhost]

TASK [Create remediation job template] *****************************************
changed: [localhost]

TASK [Reconnect profile in compliance backend (if available)] ******************
skipped: [localhost]

TASK [Report installation result] **********************************************
ok: [localhost] => {
    "msg": "=== DISA STIG Windows Server Profile Installed ===\nAssessment JT: compliance-scan-stig-windows (id=42)\nRemediation JT: compliance-remediate-stig-windows (id=43)\nFramework: DISA_STIG\nVersion: V2R7\nBackend: skipped (no BACKSTAGE_API_URL)\n"
}

PLAY RECAP **********************************************************************
localhost                  : ok=4    changed=2    unreachable=0    failed=0
```

## Step 4: Verify Installation

### Verify Job Templates

Navigate to **Resources > Templates** in Controller and verify:

| Template Name | Playbook | Inventory | EE |
|---------------|----------|-----------|-----|
| `compliance-scan-stig-windows` | `scan.yml` | `compliance-windows-inventory` | `compliance-windows-stig` |
| `compliance-remediate-stig-windows` | `remediate-windows-stig.yml` | `compliance-windows-inventory` | `compliance-windows-stig` |

### Run a Test Scan

Launch the assessment JT:

```bash
# Via API
curl -k -X POST -H "Authorization: Bearer $AAP_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"extra_vars": {"compliance_target_hosts": "windows"}}' \
  $AAP_HOST/api/v2/job_templates/42/launch/

# Via GUI
# Navigate to Templates > compliance-scan-stig-windows > Launch
```

Monitor the job output for:
- WinRM connectivity success
- SCAP datastream transfer
- SCC scan execution
- CFF normalization

### Verify CFF Output

The scan produces CFF JSON in the job's artifact directory:

```bash
# Find job ID
JOB_ID=$(curl -s -k -H "Authorization: Bearer $AAP_API_TOKEN" \
  $AAP_HOST/api/v2/jobs/?name__icontains=scan-stig-windows | jq -r '.results[0].id')

# View CFF output
curl -s -k -H "Authorization: Bearer $AAP_API_TOKEN" \
  $AAP_HOST/api/v2/jobs/$JOB_ID/stdout/?format=json | jq '.stdout' | grep -A 20 'compliance_report.json'
```

## What install.yml Creates

### Assessment Job Template

**Name**: `compliance-scan-stig-windows`

**Settings**:
- **Playbook**: `collections/ansible_collections/security/compliance_windows/playbooks/scan.yml`
- **Inventory**: `compliance-windows-inventory`
- **EE**: `compliance-windows-stig`
- **Privilege Escalation**: Enabled (`become_enabled: true`)
- **Variables on Launch**: Enabled (`ask_variables_on_launch: true`)
- **Inventory on Launch**: Enabled (`ask_inventory_on_launch: true`)

**Default Extra Vars**:

```json
{
  "profile_slug": "windows-server-stig",
  "profile_name": "DISA STIG Windows Server",
  "framework": "DISA_STIG",
  "version": "V2R7",
  "scanner": "scc",
  "remediate_jt_name": "compliance-remediate-stig-windows",
  "remediation_playbook": "collections/ansible_collections/security/compliance_windows/playbooks/remediate-windows-stig.yml",
  "display_config": {
    "gauge_label": "compliance rate",
    "gauge_unit": "rules",
    "severity_map": {
      "CAT_I": "CAT I (High)",
      "CAT_II": "CAT II (Medium)",
      "CAT_III": "CAT III (Low)"
    }
  }
}
```

### Remediation Job Template

**Name**: `compliance-remediate-stig-windows`

**Settings**:
- **Playbook**: `collections/ansible_collections/security/compliance_windows/playbooks/remediate-windows-stig.yml`
- **Inventory**: `compliance-windows-inventory`
- **EE**: `compliance-windows-stig`
- **Privilege Escalation**: Enabled
- **Tags on Launch**: Enabled (`ask_tags_on_launch: true`)
- **Variables on Launch**: Enabled
- **Limit on Launch**: Enabled (`ask_limit_on_launch: true`)

No default extra vars. Tags and variables are passed at launch time by the Ansible Portal compliance plugin.

## Post-Installation Configuration

### Configure Portal Integration

If using Ansible Portal compliance dashboard:

1. Navigate to **Compliance > Settings**
2. Click **Add Profile**
3. Fill in:
   - **Assessment JT**: Select `compliance-scan-stig-windows`
   - Auto-populated fields will appear from JT extra_vars
4. Click **Save**

### Configure Notifications

Add notifications to the assessment JT:

1. Navigate to **Templates > compliance-scan-stig-windows**
2. Click **Notifications**
3. Add notification for **On Failure** (email or Slack)

### Schedule Recurring Scans

Create a schedule for periodic scanning:

1. Navigate to **Templates > compliance-scan-stig-windows**
2. Click **Schedules**
3. Add schedule:
   - **Name**: `Weekly STIG Scan`
   - **Frequency**: Weekly (Sunday at 2 AM)
   - **Inventory**: `compliance-windows-inventory`

## Uninstallation

Remove the profile via `uninstall.yml`:

```bash
ansible-playbook uninstall.yml \
  -e aap_host=https://controller.example.com \
  -e aap_token=<your-token>
```

This removes:
- Assessment job template
- Remediation job template

**Note**: Uninstall does NOT remove:
- Execution environment
- Inventory
- Credentials
- Scan history

To fully clean up, manually delete these resources in Controller.

## Troubleshooting

### install.yml fails with "Organization not found"

Verify the organization exists:

```bash
curl -s -k -H "Authorization: Bearer $AAP_API_TOKEN" \
  $AAP_HOST/api/v2/organizations/ | jq '.results[] | .name'
```

Pass the correct org name:

```bash
ansible-playbook install.yml -e organization=MyOrg
```

### Job template already exists

install.yml creates JTs with `failed_when: false` to support idempotent runs. If a JT already exists, the playbook skips creation and reports the existing ID.

To force recreation, delete the JTs manually first:

```bash
# Find JT ID
JT_ID=$(curl -s -k -H "Authorization: Bearer $AAP_API_TOKEN" \
  $AAP_HOST/api/v2/job_templates/?name=compliance-scan-stig-windows | jq -r '.results[0].id')

# Delete JT
curl -k -X DELETE -H "Authorization: Bearer $AAP_API_TOKEN" \
  $AAP_HOST/api/v2/job_templates/$JT_ID/
```

### Backstage backend connection refused

The backend registration task is optional and fails silently if Backstage is not available:

```yaml
failed_when: false
```

To skip this task entirely, do not set `BACKSTAGE_API_URL`.

### WinRM authentication failed

Verify CredSSP is enabled on targets:

```powershell
# On Windows target
Get-WSManCredSSP
# Should show: "The machine is configured to allow delegating fresh credentials"
```

Enable CredSSP if not configured:

```powershell
Enable-WSManCredSSP -Role Server -Force
```

On the Ansible control node (EE), ensure `requests-credssp` is installed:

```bash
pip3 list | grep credssp
# Should show: requests-credssp 2.0.0
```

### Scan fails with "SCAP datastream not found"

Verify SCAP content exists in the EE:

```bash
podman run --rm -it aap-netrunner.demoredhat.com/compliance-windows-stig:latest ls -lh /usr/share/xml/scap/disa/stig/
```

If missing, rebuild the EE with SCAP content included (see [EE Build Guide](ee-build-guide.md)).
