> **EXPERIMENTAL** - This collection is a proof of concept and is not production ready.
> Modules may use placeholder API endpoints and have not been validated against real infrastructure.
> Do not use in production environments.

# security.compliance_windows

Compliance profile wrapper collection for Windows Server DISA STIG and CIS Benchmarks.

## Overview

This collection wraps [infra.windows_ops](https://github.com/redhat-cop/infra.windows_ops) to provide:

- **Pipeline playbooks** for scan, remediate, and verify workflows
- **CFF normalization** — transforms results to Common Findings Format for dashboard integration
- **PowerSTIG scanner option** — alternative DSC-native scanning with CFF output
- **EE profiles** — pre-built execution environment definitions with WinRM dependencies
- **Backstage/RHDH discovery** — metadata for automated compliance profile discovery
- **Track A pre-assessment** — `compliance_gather` for single-round-trip data collection

## Requirements

- Ansible Core >= 2.16
- `infra.windows_ops` >= 2.0.1
- `ansible.windows` >= 2.0.0
- Python: `pywinrm`, `requests-credssp`, `requests-ntlm`

## Quick Start

### Scan (audit-only)

```bash
ansible-playbook security.compliance_windows.scan-windows-stig \
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

## Roles

| Role | Description |
|------|-------------|
| `normalize_stig_findings` | Transform STIG results to CFF JSON |
| `normalize_cis_findings` | Transform CIS results to CFF JSON |
| `normalize_powerstig` | Run PowerSTIG scan and normalize to CFF |
| `compliance_gather` | Collect registry, policies, services in one WinRM call |
| `compliance_evaluate` | Evaluate gathered facts against rule definitions on localhost |

## Scanner Selection

Set `compliance_scanner` to choose the scan engine:

- `ansible` (default) — uses infra.windows_ops roles
- `powerstig` — uses PowerSTIG DSC modules

## License

Apache-2.0

## Community

- [Contributing](CONTRIBUTING.md) - How to contribute to this project
- [Code of Conduct](CODE_OF_CONDUCT.md) - Ansible Community Code of Conduct
- [Security Policy](SECURITY.md) - How to report security vulnerabilities
- [License](COPYING) - GPL-3.0

