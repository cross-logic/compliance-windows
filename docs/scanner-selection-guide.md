# Scanner Selection Guide

This guide helps you choose between the two STIG scanner backends available in the `security.compliance_windows` collection. Both scanners produce identical Common Findings Format (CFF) output and integrate with the same compliance dashboard.

## Scanner Comparison

| | DISA SCC (default) | PowerSTIG |
|---|---|---|
| **Certification** | SCAP 1.3 Validated (NIST) | Uncertified |
| **STIG coverage** | ~100 automated rules (varies by MAC level) | 83% (206/247 rules) |
| **Prerequisites on target** | None (portable deployment) | Active Directory domain membership |
| **Prerequisites in EE** | unzip, SCAP benchmarks | None |
| **Network requirements** | Download from dl.dod.cyber.mil (cached) | None at scan time |
| **Standalone hosts** | Supported | Not supported (see below) |
| **Remediation engine** | Separate (infra.windows_ops or PowerSTIG) | Same DSC engine (Start-DscConfiguration) |
| **Scan playbook** | `run_scc.yml` | `run_powerstig.yml` |
| **Output format** | XCCDF XML → CFF via normalize_xccdf module | DSC JSON → CFF via filter plugin |
| **License** | Public domain (free, not open source) | MIT (open source) |

## When to Use DISA SCC (Recommended Default)

Choose SCC when:

- **Standalone or domain-joined hosts** — SCC works on any Windows Server, regardless of Active Directory membership
- **DISA audit certification required** — SCC produces SCAP 1.3 validated results accepted for DoD RMF, FedRAMP, and NIST assessments
- **XCCDF result archival** — SCC produces standard XCCDF XML importable into STIG Viewer, eMASS, or other DoD tools
- **No pre-installation on targets** — SCC is deployed portably at scan time, zero persistent footprint

**Expected SCC results** (MAC-1_Classified, Windows Server 2022 STIG):
- ~100 automated rules evaluated
- ~162 not_applicable (manual review or not configured)
- ~23 manual review required
- Total: 285 rules in the STIG

**Note**: Windows Server 2025 SCAP benchmarks are pending release from NIWC Atlantic. WS2025 scans currently use the WS2022 benchmark with CPE override.

## When to Use PowerSTIG

Choose PowerSTIG when:

- **All targets are domain-joined** — PowerSTIG requires Active Directory domain membership with certificate infrastructure
- **Scan + remediation symmetry** — the same DSC engine handles both auditing (`Test-DscConfiguration`) and remediation (`Start-DscConfiguration`)
- **Zero network overhead** — no file transfer; DSC is already on the target
- **EDR/AV-sensitive environments** — DSC is a signed Microsoft component, already allowlisted by endpoint protection

### PowerSTIG Limitations

PowerSTIG's `Test-DscConfiguration -ReferenceConfiguration` is **not supported on standalone (non-domain-joined) hosts** on any Windows Server version (2016–2025). This is a fundamental limitation of DSC's audit model, not a version-specific regression. Evidence:

- WS2016: Ansible-win_dsc #22, SqlServerDsc #11
- WS2019: PowerSTIG #914
- WS2022: PowerSTIG #1262
- WS2025: Our testing (confirmed across 4+ lab runs)

If your hosts are not domain-joined, use SCC.

## Using Both Scanners

Set `scanner_mode: both` during installation to create two scan Job Templates sharing one remediation JT:

```bash
ansible-playbook install.yml \
  -e aap_host=https://controller.example.com \
  -e aap_token=<token> \
  -e scanner=both
```

This creates:

| Job Template | Playbook | Scanner |
|---|---|---|
| `compliance-scan-stig-windows-scc` | `run_scc.yml` | SCC (default, daily use) |
| `compliance-scan-stig-windows` | `run_powerstig.yml` | PowerSTIG (domain-joined only) |
| `compliance-remediate-stig-windows` | `remediate-windows-stig.yml` | Shared |

Both scan JTs feed findings to the same compliance profile. The dashboard shows results from whichever scanner ran most recently.

## Scale Considerations

### DISA SCC at Scale

- **File transfer** — SCC directory (~80 MB) copied from EE to each target via WinRM. Set `scc_share_path` to a UNC path (e.g. `\\fileserver\compliance\scc`) to pull from a network share instead, reducing WinRM overhead to near zero
- **SCAP content** — one matching benchmark (~240 KB) per host (OS version auto-detected)
- **Scan time** — ~5 minutes per host with selective benchmark enablement
- **Parallelism** — limited only by Ansible forks setting
- **Total per-host overhead** — ~80 MB upload + ~80 MB cleanup per scan cycle
- **EDR considerations** — some endpoint detection tools flag unfamiliar executables; SCC's `cscc.exe` may trigger alerts on locked-down systems
- **Change management** — deploying executables to production servers may be classified as a change event depending on organizational policy

### PowerSTIG at Scale

- **No file transfer** — DSC is already on the target, no binaries to copy
- **Scan time** — `Test-DscConfiguration` typically completes in 30-90 seconds per host
- **Parallelism** — limited only by Ansible forks setting
- **Memory** — CFF JSON output is ~2-5 MB per host

### Bandwidth at Fleet Scale

| Fleet Size | SCC Network | PowerSTIG Network |
|---|---|---|
| 10 hosts | ~800 MB | ~0 |
| 100 hosts | ~8 GB | ~0 |
| 1,000 hosts | ~80 GB | ~0 |

SCC network overhead is internal (EE to targets), not internet traffic. The SCC bundle is downloaded once from dl.dod.cyber.mil to the EE and cached.

## Air-Gapped Environments

### DISA SCC

Pre-stage the SCC bundle on the execution node:

```bash
# Download on a connected machine, transfer to the execution node:
scp scc-5.14_Windows_bundle.zip ee-node:/tmp/compliance-scc/
# Verify: sha256sum scc-5.14_Windows_bundle.zip
# Expected: 3f6491cbe3975bd4432ab01b694599e26e068f13de3a21757371791572ca1ebb
```

The scan playbook checks for a cached copy at `/tmp/compliance-scc/` before attempting to download. SCAP benchmarks are pre-baked in the EE (public domain, freely redistributable).

### PowerSTIG

Install the PowerSTIG module on targets before scanning:

```powershell
# On each target (or via group policy / SCCM):
Install-Module -Name PowerSTIG -Force -Scope AllUsers
```

No further connectivity is required — DSC and PowerSTIG run entirely locally.

## Decision Tree

```
                    Targets domain-joined with AD + certs?
                              /           \
                           No              Yes
                            |               |
                     Use SCC           Need SCAP 1.3 certification?
                     (only option)          /           \
                                         Yes             No
                                          |               |
                                    Use SCC          Want scan/remediation
                                          |          symmetry via DSC?
                                   Also want DSC          /        \
                                   remediation?        Yes          No
                                      /     \           |            |
                                   Yes       No    Use PowerSTIG  Use SCC
                                    |         |
                              Use both    Use SCC only
```

## scanner_mode Reference

| Value | Scan JTs Created | Default |
|---|---|---|
| `scc` | `compliance-scan-stig-windows-scc` | Yes |
| `powerstig` | `compliance-scan-stig-windows` | No |
| `both` | Both of the above | No |

Set via `-e scanner=<mode>` when running `install.yml`. The `uninstall.yml` removes all known JT names regardless of which mode was used.
