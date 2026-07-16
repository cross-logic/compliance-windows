# Windows Server STIG Scanning — Research & Architecture Reference

Comprehensive reference for Windows Server DISA STIG compliance scanning
via Ansible, covering scanner selection, SCAP content coverage, SCC usage,
DSC limitations, and content lifecycle management.

**Decision (Jul 16, 2026)**: DISA SCC is the default scanner. PowerSTIG
(DSC-based) is secondary, restricted to domain-joined hosts with
certificate infrastructure.

---

## STIG/SCAP Coverage by Windows Server Version

| | **WS2016** | **WS2019** | **WS2022** | **WS2025** |
|---|---|---|---|---|
| **DISA STIG** | V2R9 | V3R9 | V2R9 | V1R2 (Mar 2026) |
| **SCAP Benchmark (XCCDF+OVAL)** | V2R8 (Jan 2025) | V3R9 (May 2026) | V2R9 (May 2026) | V1R0 (May 2026) |
| **Automated rules** | ~200+ | 203 (19 CAT I, 176 CAT II, 8 CAT III) | 204 (18 CAT I, 178 CAT II, 8 CAT III) | 137 (14 High, 121 Medium, 2 Low) |
| **SCAP format** | 1.3 (DISA) / 1.4 (NIWC) | 1.3 / 1.4 | 1.3 / 1.4 | 1.3 only (no NIWC enhanced yet) |
| **NIWC enhanced?** | Yes (sunset path) | Yes (active) | Yes (active) | Not yet |
| **Status** | Sunset — MS extended support ends Jan 2027 | Active, quarterly updates | Active, quarterly updates | New, expect rapid iteration |
| **Download** | [public.cyber.mil/stigs/scap/](https://public.cyber.mil/stigs/scap/) | Same | Same | Same |

### Key observations

- **WS2025 SCAP benchmark exists** (V1R0, May 28 2026) — 137 rules vs 200+
  for mature versions. No NIWC enhanced (SCAP 1.4) content yet.
- **WS2016** is on the sunset path. Last SCAP update Jan 2025.
- **WS2019 and WS2022** are the sweet spot — actively maintained with
  quarterly updates and NIWC-enhanced SCAP 1.4 content.
- **SCAP 1.3 vs 1.4**: DISA publishes 1.3. NIWC Atlantic re-publishes
  enhanced versions in 1.4 (adds manual OCIL checks for 100% coverage).
  SCAP 1.4 requires SCC 5.11+.

---

## DISA SCC (SCAP Compliance Checker) Reference

### Correct CLI Usage

| Flag | Purpose |
|------|---------|
| `-u <path>` | Output/results directory |
| `-f <file>` | Host file for remote scanning |
| `-h <hostname>` | Single remote host |
| `-d` | Debug mode |
| `-x` | Validate XML files |
| `--config` | Interactive configuration menu |
| `--setOpt <key> <value>` | Override configuration option at runtime |
| `-?` | Help |

**Common incorrect assumptions** (validated Jul 16 2026):
- `-u` is NOT "unattended mode" — it is the output path
- `--scap`, `--output`, `--setOpt flat_results=true` do NOT exist
- To flatten output: use 7 separate `--setOpt` calls (see below)

**Correct scan command:**
```
cscc.exe -u C:\Temp\results ^
  --setOpt dirAllSessionsEnabled 0 ^
  --setOpt dirContentTypeEnabled 0 ^
  --setOpt dirSessionEnabled 0 ^
  --setOpt dirSessionResultsEnabled 0 ^
  --setOpt dirStreamNameEnabled 0 ^
  --setOpt dirTargetNameEnabled 0 ^
  --setOpt dirXMLEnabled 0
```

Sources:
- [SCC automation guide](https://www.careermentorgroup.com/post/automating-scap-compliance-checks-with-scc-scans-and-gitlab)
- [NRAO SCAP instructions](https://safe.nrao.edu/wiki/bin/view/HPC/DetailedSCAPInsructions)

### SCC Content Model

SCC does NOT accept external SCAP content via CLI flags. It manages its
own internal content library:

1. **Content directory**: `Resources/Content/SCAP12_Content/` (or SCAP14)
   within the SCC installation directory
2. **Configuration**: `options.xml` in the SCC root directory tracks enabled
   content streams and selected profiles
3. **SCC ships empty** — benchmarks must be downloaded separately and
   installed
4. **Content installation**: GUI "Install" button, `cscc --config` CLI menu,
   or direct file placement in `Resources/Content/`
5. **After installing**: content must be **enabled** and a **profile selected**

**Content sources:**
- [public.cyber.mil/stigs/scap/](https://public.cyber.mil/stigs/scap/) — DISA SCAP 1.3 benchmarks
- [NIWC Atlantic GitHub](https://github.com/niwc-atlantic/scap-content-library) — enhanced SCAP 1.4

### SCC Portable Deployment

- Extract the portable ZIP (inside the DISA bundle ZIP — it's a ZIP within a ZIP)
- Bundle structure: outer ZIP → `scc-<ver>_Windows/scc-<ver>_Windows.zip` → `scc_<ver>/cscc.exe`
- Contains `cscc.exe` (CLI), `scc.exe` (GUI), libraries, `options.xml`
- Cleanup: delete the directory (no registry, no uninstaller)
- **Must run from its own directory** (`chdir` required) so it finds `options.xml`

### SCC Output

- Results go to the path specified by `-u <path>`
- Default nested structure: `Sessions/<date>/ContentType/Session/Results/Stream/Target/XML/`
- Flattened with the 7 `--setOpt dirXxxEnabled 0` calls
- Produces: XCCDF XML, OVAL XML, and ARF XML
- XCCDF result files contain "XCCDF" in the filename
- Find pattern: `*XCCDF*.xml` (case-insensitive)

---

## Multi-Version Scanning via CPE Auto-Selection

SCC supports loading ALL Windows Server benchmarks (WS2016–2025) simultaneously.
The SCAP standard's **CPE (Common Platform Enumeration)** mechanism handles
per-host version matching automatically — no Ansible-side OS detection needed.

### How it works

1. Each benchmark contains `<xccdf:platform>` elements with CPE identifiers
   (e.g., `cpe:/o:microsoft:windows_server_2022`)
2. SCC runs CPE-OVAL checks against each target to determine its OS
3. Non-matching benchmarks are skipped (rules marked `notapplicable`)
4. Only the matching benchmark produces real pass/fail results

This is mandated by the SCAP specification (NIST SP 800-126). SCC, as a
[NIST SCAP-validated product](https://csrc.nist.gov/projects/scap-validation-program/validated-products-and-modules/147),
must correctly implement CPE applicability.

The SCC User Manual confirms this with a "Run All Content (Ignore CPE
Applicability)" override option — its existence proves CPE filtering is
the default behavior.

### Mixed-version inventories

A single SCC deployment with all 4 benchmarks enabled can scan a mixed
inventory (WS2019 + WS2022 + WS2025 hosts). CPE handles per-host selection.
SCC generates result files for all enabled benchmarks per host — non-matching
ones contain only `notapplicable` results. Our normalizer already skips
`notapplicable` (in `SKIP_STATUSES`).

Source: [SCC automation guide](https://www.careermentorgroup.com/post/automating-scap-compliance-checks-with-scc-scans-and-gitlab)
— "there is only one Windows SCC package which can subsequently scan any
Windows machine."

---

## SCC Licensing and Distribution

### Risk assessment by distribution model

| Model | Risk | Analysis |
|-------|------|----------|
| Ephemeral download from dl.dod.cyber.mil | **LOW** | Chocolatey precedent — automate user's own download |
| SCAP content pre-baked in EE | **LOW** | Public domain (17 USC 105, NIWC GitHub LICENSE.md) |
| Pre-configured options.xml in EE | **NONE** | Our configuration, no SCC IP |
| SCC binary cached on execution node | **LOW-MEDIUM** | Standard caching, not redistribution |
| SCC binary baked into EE image | **HIGH** | Redistribution — conflicts with Ignyte exclusive deal |
| SCC binary stored in PAH | **HIGH** | Same as above |

### Key legal facts

- SCC binary: public domain (17 USC 105), Distribution Statement A, BUT
  source code is trade secret with exclusive commercial license to Ignyte
- SCAP benchmarks: public domain, freely redistributable
- SCC EULA text is not publicly available outside installer/manual appendix
- No vendor precedent for embedding SCC binaries in commercial products
- Chocolatey downloads at install time, never embeds

### Conclusion

**Ephemeral download + pre-baked content** is the correct model:
- We ship SCAP benchmarks + options.xml in the EE (safe, public domain)
- SCC binary is downloaded from DISA at scan time (never redistributed by us)
- Cache on execution node for subsequent scans
- Air-gapped: user manually places SCC bundle following our docs

Sources:
- [NIWC/Ignyte licensing agreement](https://www.niwcatlantic.navy.mil/Media/Article/3432729/)
- [Chocolatey SCC package](https://community.chocolatey.org/packages/scap-compliance-checker)
- [DVIDS: SCC for Public Use](https://www.dvidshub.net/news/391602/)
- Existing analysis: `review/disa-scc-legal-distribution-analysis.md`

---

## Recommended Deployment Architecture

```
EE Build Time (safe to redistribute):
  ├── SCAP benchmark ZIPs (WS2016, WS2019, WS2022, WS2025) — public domain
  ├── Pre-configured options.xml (all 4 benchmarks enabled) — our config
  └── Ansible collection (playbooks, normalizer) — our code

Scan Time (ephemeral):
  1. Download SCC portable ZIP from dl.dod.cyber.mil (cache on EE node)
  2. Extract SCC, inject our content + options.xml into Resources/Content/
  3. Deploy configured SCC to Windows targets
  4. cscc.exe -u <results_dir> — CPE auto-selects correct benchmark
  5. Fetch XCCDF results, cleanup SCC from targets
  6. Normalize to CFF, POST to dashboard API
```

Benefits:
- Single artifact for all Windows Server versions (2016–2025)
- Automatic version matching via CPE (no Ansible OS-detection logic)
- Legal safety — SCC binary never redistributed
- Content lifecycle — update benchmark ZIPs quarterly, rebuild EE
- Air-gap support — cache persists after first download

---

## Content Lifecycle Management

### DISA Release Cycle

- **Quarterly**: end of January, April, July, October
- **Out-of-cycle**: individual STIGs can release between quarters
- **Changes**: new rules, updated OVAL logic, severity re-categorization,
  deprecated rules, NIST 800-53 mapping updates
- **Schedule**: [cyber.mil/stigs/quarterly-release-schedule](https://www.cyber.mil/stigs/quarterly-release-schedule-and-summary/)

### Content Update Workflow

```
DISA quarterly release
  → Download new benchmark ZIPs from public.cyber.mil/stigs/scap/
    → Place in ee/_build/scap-content/ (replaces previous versions)
      → Update options.xml if new content streams added
        → Rebuild EE → push to PAH
          → Next scan uses new content automatically
```

### options.xml Management

- Plain XML file stored in `ee/_build/scc-config/options.xml`
- Initial creation: configure one SCC instance via `cscc --config` or GUI
  on a Windows host, export the resulting `options.xml`
- Enable all Windows Server benchmarks + select appropriate profiles
- At scan time: Ansible injects this file into the downloaded SCC's directory
- Do NOT try to programmatically generate from scratch (undocumented internal
  structure) — configure-and-copy is the supported pattern

### Version Tracking

The dashboard should record which benchmark version was used for each scan.
When a benchmark version changes:
- New rules may appear (previously passing hosts now have findings)
- Removed rules drop out of results
- Updated OVAL checks may change pass/fail outcomes
- This is expected behavior, not regression

---

## PowerSTIG (DSC-Based Scanner) — Secondary

### Why secondary

`Test-DscConfiguration -ReferenceConfiguration` is unsupported on standalone
hosts across ALL Windows Server versions (2016–2025). The error class
("Could not find mandatory property") has been reported on:

| Version | Issue |
|---------|-------|
| WS2016 | [Ansible-win_dsc #22](https://github.com/trondhindenes/Ansible-win_dsc/issues/22) |
| WS2019 | [PowerSTIG #914](https://github.com/microsoft/PowerStig/issues/914) |
| WS2022 | [PowerSTIG #1262](https://github.com/microsoft/PowerStig/issues/1262) |
| WS2025 | Our testing (Controller jobs 4286–4335) |

No confirmed success on standalone hosts on any version. DSCEA (Microsoft's
own audit tool) explicitly requires Active Directory domain membership.

### Root cause

The LCM (`MSFT_DSCLocalConfigurationManager`) fails when processing
credential-related content in the compiled MOF. On standalone hosts without
AD or certificate infrastructure, these properties cannot be validated.

The `NTFSAccessControlEntry` initially suspected was a red herring — its
schema has no Thumbprint property. The error is from the LCM's own
meta-configuration validation path.

### What was ruled out (Jul 16, 4 lab runs)

1. NOT the LCM MetaConfig (reset to Push, CertificateID null)
2. NOT a stale meta.mof (compilation produces only localhost.mof, 304KB)
3. NOT credential encryption (PowerSTIG runs as SYSTEM, no certs needed)
4. NOT the LCM RefreshMode (Disabled blocks Test entirely; Push hits Thumbprint)

### Requirements for PowerSTIG (domain-joined only)

- Active Directory domain membership
- Certificate infrastructure for credential encryption
- LCM configured with valid CertificateID
- Domain Controller accessible for UserRightRule evaluation
- Coverage: 83% (206/247 rules for WS2022)

### Ansible collection limitations

- `win_dsc` blocks composite resources (PowerSTIG's `WindowsServer` is composite)
- `dsc3` (ansible.windows 3.4.0+) uses DSC v3 — PowerSTIG doesn't support it
- `Invoke-DscResource` bypasses LCM but requires MOF parsing (complex)

---

## Key References

### SCC
| Source | URL |
|--------|-----|
| SCC automation guide | https://www.careermentorgroup.com/post/automating-scap-compliance-checks-with-scc-scans-and-gitlab |
| NIWC Atlantic content library | https://github.com/niwc-atlantic/scap-content-library |
| DISA SCAP downloads | https://public.cyber.mil/stigs/scap/ |
| SCC NIST validation #147 | https://csrc.nist.gov/projects/scap-validation-program/validated-products-and-modules/147 |
| NRAO SCAP instructions | https://safe.nrao.edu/wiki/bin/view/HPC/DetailedSCAPInsructions |

### PowerSTIG / DSC
| Source | URL |
|--------|-----|
| PowerSTIG Wiki | https://github.com/microsoft/PowerStig/wiki |
| PowerSTIG Issue #914 (WS2019) | https://github.com/microsoft/PowerStig/issues/914 |
| PowerSTIG Issue #1262 (WS2022) | https://github.com/microsoft/PowerStig/issues/1262 |
| Microsoft DSC securemof | https://learn.microsoft.com/en-us/powershell/dsc/pull-server/securemof |
| WS2025 DSC breaking changes | https://mehic.se/2026/02/07/desired-state-configuration-dsc-windows-server-2025-and-rds-2025-nightmare-and-solution/ |
| ansible.windows win_dsc source | https://github.com/ansible-collections/ansible.windows/blob/main/plugins/modules/win_dsc.ps1 |
| ansible-lockdown Windows-2022-STIG | https://github.com/ansible-lockdown/Windows-2022-STIG |

### General
| Source | URL |
|--------|-----|
| DISA STIG quarterly schedule | https://www.cyber.mil/stigs/quarterly-release-schedule-and-summary/ |
| DISA SCC legal analysis | (repo) review/disa-scc-legal-distribution-analysis.md |
| DSC v3 migration guide | https://patchmypc.com/blog/desired-state-configuration-v3-explained-what-changed-why-it-matters-and-how-to-migrate/ |
