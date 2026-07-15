# Scanner Selection Guide

This guide helps you choose between the two STIG scanner backends available in the `security.compliance_windows` collection. Both scanners produce identical Common Findings Format (CFF) output and integrate with the same compliance dashboard.

## Scanner Comparison

| | PowerSTIG (default) | DISA SCC |
|---|---|---|
| **Certification** | Uncertified | SCAP 1.3 Validated |
| **STIG coverage** | 83% (206/247 rules) | 100% (247 rules) |
| **Prerequisites on target** | PowerSTIG PowerShell module | None (portable deployment) |
| **Prerequisites in EE** | None (DSC is built into Windows) | unzip, curl, SCAP benchmarks |
| **Network requirements** | None at scan time | Download from dl.dod.cyber.mil (cached) |
| **Remediation engine** | Same DSC engine (Start-DscConfiguration) | Separate (infra.windows_ops or PowerSTIG) |
| **Scan playbook** | `run_powerstig.yml` | `run_scc.yml` |
| **Output format** | DSC JSON → CFF via filter plugin | XCCDF XML → CFF via normalize_xccdf module |
| **License** | MIT (open source) | Public domain (free, not open source) |

## When to Use PowerSTIG (Recommended Default)

Choose PowerSTIG when:

- **Daily operational scanning** — no external downloads, faster scan cycles
- **Air-gapped environments** — only needs the PowerSTIG module pre-installed on targets, no internet connectivity required at scan time
- **Scan + remediation symmetry** — the same DSC engine handles both auditing (`Test-DscConfiguration`) and remediation (`Start-DscConfiguration`)
- **Change management constraints** — running a PowerShell cmdlet is not classified as a software installation event, unlike deploying SCC binaries
- **EDR/AV-sensitive environments** — DSC is a signed Microsoft component, already allowlisted by endpoint protection

## When to Use DISA SCC

Choose SCC when:

- **DISA audit certification required** — SCC produces SCAP 1.3 validated results accepted for DoD RMF, FedRAMP, and NIST assessments
- **Full STIG coverage needed** — SCC evaluates all 247 STIG rules versus PowerSTIG's 206
- **Existing SCC investment** — teams already familiar with SCC workflows and result formats
- **XCCDF result archival** — SCC produces standard XCCDF XML that can be imported into STIG Viewer, eMASS, or other DoD tools

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
| `compliance-scan-stig-windows` | `run_powerstig.yml` | PowerSTIG (daily use) |
| `compliance-scan-stig-windows-scc` | `run_scc.yml` | SCC (audit evidence) |
| `compliance-remediate-stig-windows` | `remediate-windows-stig.yml` | Shared |

Both scan JTs feed findings to the same compliance profile. The dashboard shows results from whichever scanner ran most recently.

## Scale Considerations

### PowerSTIG at Scale

- **No file transfer** — DSC is already on the target, no binaries to copy
- **Scan time** — `Test-DscConfiguration` typically completes in 30-90 seconds per host
- **Parallelism** — limited only by Ansible forks setting
- **Memory** — CFF JSON output is ~2-5 MB per host

### DISA SCC at Scale

- **File transfer** — SCC directory (~80 MB) copied from EE to each target via WinRM
- **SCAP content** — benchmarks (~6 MB) also copied per host
- **Total per-host overhead** — ~86 MB upload + ~86 MB cleanup per scan cycle
- **MSI mutex** — if another Windows Installer operation is running on a host, SCC portable deployment is unaffected (no MSI install required)
- **EDR considerations** — some endpoint detection tools flag unfamiliar executables; SCC's `cscc.exe` may trigger alerts on locked-down systems
- **Change management** — deploying executables to production servers may be classified as a change event depending on organizational policy

### Bandwidth at Fleet Scale

| Fleet Size | PowerSTIG Network | SCC Network |
|---|---|---|
| 10 hosts | ~0 | ~860 MB |
| 100 hosts | ~0 | ~8.6 GB |
| 1,000 hosts | ~0 | ~86 GB |
| 10,000 hosts | ~0 | ~860 GB |

SCC network overhead is internal (EE to targets), not internet traffic. The SCC bundle is downloaded once from dl.dod.cyber.mil to the EE and cached.

## Air-Gapped Environments

### PowerSTIG

Install the PowerSTIG module on targets before scanning:

```powershell
# On each target (or via group policy / SCCM):
Install-Module -Name PowerSTIG -Force -Scope AllUsers
```

No further connectivity is required — DSC and PowerSTIG run entirely locally.

### DISA SCC

Pre-stage the SCC bundle on the execution node:

```bash
# Download on a connected machine, transfer to the execution node:
scp scc-5.10.2_Windows_bundle.zip ee-node:/tmp/compliance-scc/
```

The scan playbook checks for a cached copy at `/tmp/compliance-scc/` before attempting to download.

## Decision Tree

```
                        Need SCAP 1.3 certification?
                              /           \
                           Yes             No
                            |               |
                     Use SCC            Use PowerSTIG
                            |               |
                  Also want daily     ─────────────
                  scanning without        Done
                  SCC overhead?
                     /        \
                   Yes         No
                    |           |
              Use both      Use SCC only
```

## scanner_mode Reference

| Value | Scan JTs Created | Default |
|---|---|---|
| `powerstig` | `compliance-scan-stig-windows` | Yes |
| `scc` | `compliance-scan-stig-windows-scc` | No |
| `both` | Both of the above | No |

Set via `-e scanner=<mode>` when running `install.yml`. The `uninstall.yml` removes all known JT names regardless of which mode was used.
