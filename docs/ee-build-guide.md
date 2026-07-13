# Execution Environment Build Guide

This guide covers building execution environments (EEs) for Windows Server compliance scanning with DISA STIG, CIS Benchmarks, and regulatory crosswalks.

## Table of Contents

- [Overview](#overview)
- [EE Profiles](#ee-profiles)
- [Build Prerequisites](#build-prerequisites)
- [Build STIG EE](#build-stig-ee)
- [Build CIS EE](#build-cis-ee)
- [EE Contents](#ee-contents)
- [Python Dependencies](#python-dependencies)
- [SCAP Benchmark Pre-baking](#scap-benchmark-pre-baking)
- [Multi-arch Support](#multi-arch-support)
- [PAH Mirroring](#pah-mirroring)
- [Troubleshooting](#troubleshooting)

## Overview

Execution environments for Windows compliance require:
- **WinRM connectivity**: Python `pywinrm`, `requests-credssp`, `requests-ntlm`
- **SCAP content**: XCCDF datastreams (STIG only, freely redistributable)
- **Collections**: `security.compliance_windows`, `infra.windows_ops`, `ansible.windows`
- **Optional**: DISA SCC binaries (downloaded at runtime, not embedded)

Two EE profiles are provided:

| Profile | Scanner | Contents | Use Case |
|---------|---------|----------|----------|
| `compliance-windows-stig` | DISA SCC | SCAP datastreams, WinRM deps | STIG scanning |
| `compliance-windows-cis` | infra.windows_ops | WinRM deps only | CIS scanning |

## EE Profiles

EE profiles are declared in `meta/ee_profile.yml` and consumed by `ansible-builder`:

```yaml
# meta/ee_profile.yml (STIG profile)
---
name: compliance-windows-stig
description: Windows Server STIG compliance scanning and remediation
version: "0.1.0"
scanner: scc
framework: DISA_STIG
supported_os:
  - windows_server_2019
  - windows_server_2022
  - windows_server_2025
dependencies:
  collections:
    - security.compliance_windows
    - infra.windows_ops>=2.0.1
    - ansible.windows>=2.0.0
  python:
    - pywinrm>=0.4.0
    - requests-credssp
    - requests-ntlm
  system: []
execution_environment:
  base_image: registry.redhat.io/ansible-automation-platform/ee-supported-rhel9:latest
  additional_build_steps:
    prepend_galaxy:
      - ansible-galaxy collection install security.compliance_windows
      - ansible-galaxy collection install infra.windows_ops
      - ansible-galaxy collection install ansible.windows
```

## Build Prerequisites

Install `ansible-builder`:

```bash
pip install ansible-builder
```

Clone the collection:

```bash
git clone https://github.com/stevefulme1/compliance-windows.git
cd compliance-windows
```

## Build STIG EE

Create an EE definition file:

```yaml
# ee/stig/execution-environment.yml
---
version: 3

images:
  base_image:
    name: registry.redhat.io/ansible-automation-platform/ee-supported-rhel9:latest

dependencies:
  galaxy:
    collections:
      - name: security.compliance_windows
      - name: infra.windows_ops
        version: ">=2.0.1"
      - name: ansible.windows
        version: ">=2.0.0"

  python:
    - pywinrm>=0.4.0
    - requests-credssp
    - requests-ntlm

  system: []

additional_build_steps:
  prepend_base: []
  append_base: []
  prepend_galaxy: []
  append_galaxy:
    - COPY scap-content /usr/share/xml/scap/disa/stig/
  prepend_builder: []
  append_builder: []
  prepend_final:
    - RUN mkdir -p /usr/share/xml/scap/disa/stig
  append_final: []
```

Add SCAP content to the build context:

```bash
mkdir -p ee/stig/scap-content
cd ee/stig/scap-content

# Download SCAP benchmarks from https://public.cyber.mil/stigs/scap/
curl -O https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2019_V3R2_STIG_SCAP_1-3_Benchmark.zip
curl -O https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2022_V2R7_STIG_SCAP_1-3_Benchmark.zip
curl -O https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_Server_2025_V1R1_STIG_SCAP_1-3_Benchmark.zip

unzip '*.zip'
cd ../..
```

Build the EE:

```bash
cd ee/stig
ansible-builder build -f execution-environment.yml -t compliance-windows-stig:latest -v3
```

Tag for registry:

```bash
podman tag compliance-windows-stig:latest aap-netrunner.demoredhat.com/compliance-windows-stig:latest
```

## Build CIS EE

CIS scanning does not require SCAP content. Create a simplified EE definition:

```yaml
# ee/cis/execution-environment.yml
---
version: 3

images:
  base_image:
    name: registry.redhat.io/ansible-automation-platform/ee-supported-rhel9:latest

dependencies:
  galaxy:
    collections:
      - name: security.compliance_windows
      - name: infra.windows_ops
        version: ">=2.0.1"
      - name: ansible.windows
        version: ">=2.0.0"

  python:
    - pywinrm>=0.4.0
    - requests-credssp
    - requests-ntlm

  system: []
```

Build:

```bash
cd ee/cis
ansible-builder build -f execution-environment.yml -t compliance-windows-cis:latest -v3
```

## EE Contents

### STIG EE Contents

| Path | Purpose | Size |
|------|---------|------|
| `/usr/share/xml/scap/disa/stig/*.xml` | SCAP datastreams (XCCDF + OVAL) | ~50 MB |
| `/usr/lib/python3.11/site-packages/pywinrm/` | WinRM client library | ~2 MB |
| `/usr/share/ansible/collections/ansible_collections/security/compliance_windows/` | This collection | ~5 MB |
| `/usr/share/ansible/collections/ansible_collections/infra/windows_ops/` | CIS content engine | ~15 MB |

**DISA SCC binaries are NOT included**. SCC is downloaded at runtime from `dl.dod.cyber.mil` due to NIWC trade secret licensing.

### CIS EE Contents

Identical to STIG EE except:
- No SCAP datastreams in `/usr/share/xml/scap/`
- Smaller image size (~200 MB vs. ~250 MB)

## Python Dependencies

Windows compliance scanning requires WinRM connectivity via Python libraries:

```python
# Python 3.11+ on RHEL 9 EE
pywinrm>=0.4.0         # WinRM client (HTTP/HTTPS, Kerberos, NTLM)
requests-credssp       # CredSSP authentication (domain join)
requests-ntlm          # NTLM authentication (workgroup)
```

These are installed automatically by `ansible-builder` via the `dependencies.python` section.

### WinRM Authentication Methods

| Method | Use Case | Requires |
|--------|----------|----------|
| **NTLM** | Workgroup hosts | `requests-ntlm` |
| **Kerberos** | Domain-joined hosts | `requests-kerberos`, `krb5-workstation` (system) |
| **CredSSP** | Domain + delegation | `requests-credssp` |
| **Basic** | Testing only (insecure) | No extra deps |

For production STIG scanning, use **CredSSP** with domain credentials.

## SCAP Benchmark Pre-baking

SCAP benchmark content is **freely redistributable** and can be embedded in the EE without licensing restrictions.

### Why Pre-bake SCAP Content?

1. **Faster scans**: No need to download 50 MB datastreams from external sources at scan time
2. **Air-gapped environments**: EE works without internet connectivity
3. **Consistency**: All scans use the same datastream version

### How to Pre-bake

Add SCAP XML files to the build context:

```bash
ee/stig/scap-content/
├── U_MS_Windows_Server_2019_STIG_V3R2_XCCDF.xml
├── U_MS_Windows_Server_2022_STIG_V2R7_XCCDF.xml
└── U_MS_Windows_Server_2025_STIG_V1R1_XCCDF.xml
```

Add a COPY step to `execution-environment.yml`:

```yaml
additional_build_steps:
  append_galaxy:
    - COPY scap-content /usr/share/xml/scap/disa/stig/
```

The scan playbook will reference these files:

```yaml
- name: Copy SCAP datastream to target
  ansible.windows.win_copy:
    src: /usr/share/xml/scap/disa/stig/U_MS_Windows_Server_{{ ansible_distribution_major_version }}_STIG_*_XCCDF.xml
    dest: C:\Windows\Temp\scap-datastream.xml
```

## Multi-arch Support

Execution environments for Windows compliance are **x86_64 only** (no ARM64 support). This matches AAP Controller's architecture requirements.

To build for a specific platform:

```bash
ansible-builder build -f execution-environment.yml -t compliance-windows-stig:latest --container-runtime podman --arch x86_64
```

## PAH Mirroring

Mirror the built EE to Private Automation Hub via `skopeo`:

```bash
# Login to registries
podman login registry.redhat.io
podman login aap-netrunner.demoredhat.com

# Build EE
ansible-builder build -f execution-environment.yml -t compliance-windows-stig:latest

# Tag for PAH
podman tag compliance-windows-stig:latest aap-netrunner.demoredhat.com/compliance-windows-stig:latest

# Push to PAH
podman push aap-netrunner.demoredhat.com/compliance-windows-stig:latest
```

Alternatively, use `skopeo` for direct registry-to-registry copy:

```bash
skopeo copy \
  docker://localhost/compliance-windows-stig:latest \
  docker://aap-netrunner.demoredhat.com/compliance-windows-stig:latest \
  --dest-creds admin:password
```

### PAH Image Path

In AAP Controller, reference the EE as:

```
aap-netrunner.demoredhat.com/compliance-windows-stig:latest
```

This assumes:
1. PAH is accessible at `aap-netrunner.demoredhat.com`
2. The `compliance-windows-stig` repository exists in PAH
3. Controller has a Container Registry Credential configured for PAH

## Troubleshooting

### Build fails with "No module named 'pywinrm'"

Python dependencies are installed in the builder stage but not the final stage. Add a `prepend_final` step:

```yaml
additional_build_steps:
  prepend_final:
    - RUN pip3 install pywinrm requests-credssp requests-ntlm
```

### SCAP content not found in EE

Verify the COPY step runs after `ansible-galaxy`:

```yaml
additional_build_steps:
  append_galaxy:
    - COPY scap-content /usr/share/xml/scap/disa/stig/
```

Check the build context includes `scap-content/`:

```bash
ls -la ee/stig/scap-content/
```

### WinRM connection refused

Verify WinRM is enabled on targets:

```powershell
# On Windows target
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $true
```

Configure Ansible to use CredSSP:

```yaml
ansible_connection: winrm
ansible_winrm_transport: credssp
ansible_winrm_server_cert_validation: ignore
```

### EE exceeds 2 GB size limit

SCAP content adds ~50 MB. If the EE is too large:
1. Remove unused collections
2. Use `dnf clean all` in a prepend_final step
3. Use a smaller base image (ee-minimal-rhel9 instead of ee-supported-rhel9)

### SCC download fails during scan

SCC is downloaded from `dl.dod.cyber.mil` at scan time. If the download fails:
1. Check execution node internet connectivity
2. Verify the download URL is accessible
3. Use a local mirror for air-gapped environments

To use a local mirror, set `scc_download_url` in playbook extra_vars:

```yaml
scc_download_url: https://local-mirror.example.com/scc/scc-latest.zip
```
