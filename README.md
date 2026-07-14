# Ansible Collection: security.compliance_windows

> **EXPERIMENTAL** - This collection is a proof of concept and is not production ready.
> Modules may use placeholder API endpoints and have not been validated against real infrastructure.
> Do not use in production environments.

Windows Server compliance profiles for DISA STIG, CIS Benchmarks, HIPAA, and PCI-DSS v4.0.

OpenSCAP-based STIG scanning with DISA SCC (certified), CIS scanning via infra.windows_ops (conformant), and centralized normalization to Common Findings Format (CFF) for Ansible Portal dashboard integration.

## Table of Contents

- [Overview](#overview)
- [Supported Platforms](#supported-platforms)
- [Supported Frameworks](#supported-frameworks)
- [Scanner Options](#scanner-options)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Collection Structure](#collection-structure)
- [Roles](#roles)
- [Playbooks](#playbooks)
- [Filter Plugins](#filter-plugins)
- [Crosswalk Profiles](#crosswalk-profiles)
- [Execution Environment](#execution-environment)
- [Installation](#installation)
- [Documentation](#documentation)
- [Communication](#communication)
- [License](#license)

## Overview

This collection provides a compliance scanning pipeline for Windows Server environments, wrapping proven content sources and normalizing results for centralized reporting:

- **DISA STIG scanning** — Uses DISA SCAP Compliance Checker (SCC) downloaded ephemerally at scan time for NIST SCAP 1.3 certified assessments
- **CIS Benchmark scanning** — Uses `infra.windows_ops` collection for CIS L1/L2 Server hardening checks (conformant, not certified)
- **Remediation playbooks** — Direct remediation via `infra.windows_ops` or PowerSTIG DSC modules
- **Common Findings Format** — All scan results normalize to CFF JSON for dashboard integration
- **Crosswalk profiles** — Maps STIG/CIS controls to HIPAA Security Rule and PCI-DSS v4.0 requirements
- **Ansible Portal integration** — Auto-discovery metadata for profile registration in compliance dashboards

## Supported Platforms

- Windows Server 2019
- Windows Server 2022
- Windows Server 2025

## Supported Frameworks

| Framework | Version | Certification | Scanner | Status |
|-----------|---------|---------------|---------|--------|
| DISA STIG | V2R7 | SCAP 1.3 Certified | DISA SCC | Active |
| CIS Benchmark L1 Server | 3.0.0 | CIS Conformant | infra.windows_ops | Active |
| CIS Benchmark L2 Server | 3.0.0 | CIS Conformant | infra.windows_ops | Active |
| HIPAA Security Rule | 2013 | Crosswalk view | N/A | Mapping only |
| PCI-DSS | v4.0 | Crosswalk view | N/A | Mapping only |

**HIPAA and PCI-DSS** are regulatory crosswalks, not standalone scanning frameworks. They map primary controls from STIG/CIS to regulatory requirements and are displayed as dashboard tabs showing control coverage status.

## Scanner Options

The collection supports three scanner backends:

| Scanner | Certification | Distribution | Use Case |
|---------|---------------|--------------|----------|
| **DISA SCC** | SCAP 1.3 Certified | Ephemeral download from dl.dod.cyber.mil | STIG compliance for DoD/FedRAMP |
| **infra.windows_ops** | Conformant (not certified) | Embedded in collection | CIS L1/L2 hardening checks |
| **PowerSTIG** | Uncertified | DSC native | Alternative STIG scanning via DSC |

**DISA SCC** is the recommended scanner for STIG assessments requiring certified SCAP results. SCC is downloaded at scan time due to NIWC trade secret licensing restrictions. SCAP benchmark content (XML datastreams) is freely redistributable and included in the execution environment.

**infra.windows_ops** provides CIS scanning with Ansible-native task execution. Results are conformant with CIS benchmarks but not CIS-certified.

**PowerSTIG** is an alternative scanner using DSC modules for STIG assessment. It is uncertified but useful for environments standardized on DSC-based configuration management.

## Requirements

- Ansible >= 2.16
- `infra.windows_ops` >= 2.0.1
- `ansible.windows` >= 2.0.0
- Python: `pywinrm`, `requests-credssp`, `requests-ntlm`
- SSH or WinRM connectivity to target Windows hosts
- Administrator credentials with `become` privileges

## Quick Start

### Scan (STIG with SCC)

```bash
ansible-playbook security.compliance_windows.scan-windows-stig \
  -i inventory.yml \
  --check
```

This runs a DISA SCC SCAP scan in audit-only mode (no changes).

### Scan (CIS with infra.windows_ops)

```bash
ansible-playbook security.compliance_windows.scan-windows-cis \
  -i inventory.yml \
  --check
```

### Remediate

```bash
ansible-playbook security.compliance_windows.remediate-windows-stig \
  -i inventory.yml \
  -e '{"compliance_skip_rules": ["V-254238"]}'
```

### Verify after remediation

```bash
ansible-playbook security.compliance_windows.verify-windows-stig \
  -i inventory.yml
```

## Collection Structure

```
security.compliance_windows/
├── playbooks/
│   ├── scan-windows-stig.yml        # DISA STIG scan with SCC
│   ├── scan-windows-cis.yml         # CIS L1/L2 scan with infra.windows_ops
│   ├── remediate-windows-stig.yml   # STIG remediation
│   ├── remediate-windows-cis.yml    # CIS remediation
│   ├── verify-windows-stig.yml      # Post-remediation verification
│   ├── scan-windows-hipaa.yml       # HIPAA crosswalk view (STIG-backed)
│   ├── scan-windows-pci.yml         # PCI-DSS crosswalk view (STIG-backed)
│   └── normalize.yml                # Standalone normalization utility
├── roles/
│   ├── normalize_stig_findings/     # Transform STIG results to CFF
│   ├── normalize_cis_findings/      # Transform CIS results to CFF
│   ├── normalize_powerstig/         # PowerSTIG scanner integration
│   ├── compliance_gather/           # Efficient WinRM data collection
│   ├── compliance_evaluate/         # Localhost rule evaluation
│   └── compliance_crosswalk/        # Regulatory control mapping
├── plugins/
│   ├── filter/
│   │   ├── cff_filters.py           # CFF transformation filters
│   │   └── crosswalk_filters.py     # Control mapping filters
│   └── modules/
│       └── (future normalization modules)
├── compliance_profiles/
│   ├── hipaa.yml                    # HIPAA Security Rule crosswalk
│   └── pci_dss_v4.yml               # PCI-DSS v4.0 crosswalk
├── meta/
│   ├── compliance-profile.yml       # Portal discovery metadata
│   ├── ee_profile.yml               # EE build definition
│   └── runtime.yml                  # Collection runtime config
├── install.yml                      # Controller profile registration
└── uninstall.yml                    # Profile removal
```

## Roles

| Role | Description | Status |
|------|-------------|--------|
| `normalize_stig_findings` | Transform DISA SCC XCCDF results to CFF JSON | Active |
| `normalize_cis_findings` | Transform infra.windows_ops CIS results to CFF JSON | Active |
| `normalize_powerstig` | Run PowerSTIG DSC scan and normalize to CFF | Active |
| `compliance_gather` | Collect registry, policies, services in one WinRM call (Track A pre-assessment) | Active |
| `compliance_evaluate` | Evaluate gathered facts against rule definitions on localhost | Active |
| `compliance_crosswalk` | Map primary controls to regulatory requirements | Active |

## Playbooks

| Playbook | Runs On | Description |
|----------|---------|-------------|
| `scan-windows-stig.yml` | Windows targets | DISA STIG scan with SCC + normalize to CFF |
| `scan-windows-cis.yml` | Windows targets | CIS L1/L2 scan with infra.windows_ops + normalize to CFF |
| `remediate-windows-stig.yml` | Windows targets | Apply STIG controls via infra.windows_ops or PowerSTIG |
| `remediate-windows-cis.yml` | Windows targets | Apply CIS controls via infra.windows_ops |
| `verify-windows-stig.yml` | Windows targets | Post-remediation scan (same as scan, different context) |
| `verify-windows-cis.yml` | Windows targets | Post-remediation CIS scan |
| `scan-windows-hipaa.yml` | Windows targets | HIPAA crosswalk view (STIG scan + crosswalk mapping) |
| `scan-windows-pci.yml` | Windows targets | PCI-DSS crosswalk view (STIG scan + crosswalk mapping) |
| `normalize.yml` | Execution node | Standalone normalization utility (debugging, Tier 2 reuse) |
| `scan.yml` | Windows targets | Generic scan dispatcher (delegates to specific profile) |
| `remediate.yml` | Windows targets | Generic remediation dispatcher |

## Filter Plugins

| Plugin | Description |
|--------|-------------|
| `cff_filters.py` | CFF JSON transformation filters (`to_cff_finding`, `cff_summary`) |
| `crosswalk_filters.py` | Control mapping filters (`map_to_hipaa`, `map_to_pci`) |

## Crosswalk Profiles

Crosswalk profiles map primary controls (STIG/CIS) to regulatory requirements (HIPAA, PCI-DSS). They are declared as dashboard tabs in `meta/compliance-profile.yml` and rendered dynamically by the Ansible Portal compliance plugin.

**HIPAA Security Rule** (45 CFR § 164.312) — Technical Safeguards:
- Access Control (164.312(a))
- Audit Controls (164.312(b))
- Integrity (164.312(c))
- Person or Entity Authentication (164.312(d))
- Transmission Security (164.312(e))

**PCI-DSS v4.0** — Technical Controls:
- System Hardening (Requirement 2)
- Anti-Malware (Requirement 5)
- Access Control (Requirement 8)
- Logging and Monitoring (Requirement 10)
- Change Detection (Requirement 11)

Each control in a crosswalk profile lists:
- `cis_rules`: CIS control IDs (e.g., `1.1.1`, `18.10.77.1`)
- `stig_rules`: STIG vulnerability IDs (e.g., `V-254239`)
- `gap`: Boolean indicating no direct technical control exists
- `gap_note`: Explanation for gaps (organizational procedure, external tool required)

Control status is computed from primary scan results:
- **Pass**: All mapped controls passed
- **Fail**: One or more mapped controls failed
- **Partial**: Some mapped controls passed, others failed
- **Gap**: No direct technical controls map to this requirement
- **Unmapped**: No controls defined for this requirement

See [docs/crosswalks.md](docs/crosswalks.md) for detailed crosswalk design and implementation.

## Execution Environment

The collection requires an execution environment with WinRM connectivity and optional SCAP content:

**For STIG scanning:**
- SCAP benchmark content (XCCDF datastreams) — freely redistributable
- DISA SCC downloaded at runtime (not embedded due to licensing)
- Python: `pywinrm`, `requests-credssp`, `requests-ntlm`

**For CIS scanning:**
- `infra.windows_ops` collection embedded
- No additional dependencies

**For PowerSTIG scanning:**
- PowerSTIG DSC modules (optional)
- PowerShell 5.1+ on targets

### Build the EE

```bash
cd ee/
ansible-builder build -f execution-environment.yml -t compliance-windows-stig:latest -v3
```

See [docs/ee-build-guide.md](docs/ee-build-guide.md) for detailed EE build instructions.

## Installation

Run `install.yml` to register the profile on AAP Controller:

```bash
export AAP_HOST=https://controller.example.com
export AAP_API_TOKEN=<token>
ansible-playbook install.yml
```

This creates:
- Assessment Job Template (scan with DISA SCC)
- Remediation Job Template (apply controls)
- Profile metadata in Controller extra_vars

See [docs/install-guide.md](docs/install-guide.md) for full installation workflow.

## Documentation

- [Scanning Guide](docs/scanning.md) — How scanning works per scanner backend
- [EE Build Guide](docs/ee-build-guide.md) — Build execution environments
- [Crosswalks Guide](docs/crosswalks.md) — Regulatory control mapping
- [Install Guide](docs/install-guide.md) — Profile registration on Controller

## Communication

- Join the [Ansible Forum](https://forum.ansible.com) for questions and discussion.
- Use the `security` and `compliance` tags when posting.
- Report issues on [GitHub](https://github.com/cross-logic/aap-compliance-pipelines/issues).

## License

GPL-3.0-only

## Author

Red Hat Ansible Automation Platform
