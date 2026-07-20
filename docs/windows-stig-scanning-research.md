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

> **[Updated Jul 17]** Selective enablement (`--disableAll` + `--enableBenchmark`)
> was attempted but **does not work reliably** — SCC returns RC=0 but produces
> zero XCCDF results despite benchmarks appearing enabled. The flags are valid
> CLI commands (confirmed via `--help`) and return RC=0, but the enable/disable
> state does not persist across separate `cscc.exe` invocations. Each CLI call
> is a standalone process that loads options.xml, modifies in-memory state,
> and may not flush changes. The pipeline uses `--enableAll` + CPE filtering
> (the proven working approach from job 4375). CPE auto-selects matching
> benchmarks per host OS. For WS2025, `ignoreCPEOVALResults=1` forces
> WS2022 benchmarks to evaluate.

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

> **[Updated Jul 17]** The pipeline now handles mixed fleets by mapping
> each host's OS build number to a benchmark via `_os_benchmark_map` in
> `run_scc.yml`. The `_benchmark_match` variable (e.g., `'2019'`, `'2022'`)
> is derived from the host's kernel build, and only benchmarks whose IDs
> contain that match string are enabled. This replaces the earlier approach
> of enabling all benchmarks and relying solely on CPE filtering.

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

## Validated Deployment Architecture (Jul 17, 2026)

Confirmed working end-to-end on Netrunner (Controller job 4375).

```
EE Build Time (safe to redistribute):
  ├── SCAP benchmark ZIPs (WS2016, WS2019, WS2022) — NIWC enhanced SCAP 1.4
  │   (from github.com/niwc-atlantic/scap-content-library, public domain)
  └── Ansible collection (playbooks, normalizer) — our code

Scan Time (ephemeral, per-target):
  Play 0 (EE/localhost):
    1. Download SCC 5.14 portable ZIP from dl.dod.cyber.mil (cache on EE)
    2. Extract inner portable ZIP (bundle is ZIP-in-ZIP)

  Play 1 (Windows targets, with rescue block for per-host failure isolation):
    3. Copy SCC from EE (or scc_share_path network share) to target
    4. Copy only the SCAP benchmark matching host OS via _benchmark_match
    5. Install benchmark: cscc --installScap <zip> MAC-3_Sensitive --force
    6. Enable all: cscc --enableAll (CPE auto-selects matching benchmarks)
    7. WS2025 only: cscc --setOpt ignoreCPEOVALResults 1 (CPE override)
    8. Scan: cscc -u <results_dir> --setOpt dirXxxEnabled 0 (×7 for flat output)
    9. Find + fetch *XCCDF*.xml results back to EE
    10. On zero results: warn + end_host (skip host, continue others)
    11. Cleanup (always): remove SCC + results from target
    On failure (timeout/WinRM): rescue block logs warning, end_host

  Play 2 (EE/localhost):
    13. Soft-fail: end_play if no XCCDF files exist (all hosts failed/skipped)
    14. Normalize XCCDF to CFF via normalize_xccdf module (per-host loop)
    15. Compose NDJSON POST body
    16. Stream to compliance API
```

### SCC CLI Reference (validated)

| Flag | Purpose | Notes |
|------|---------|-------|
| `-u <path>` | User results directory | Directory must pre-exist |
| `--installScap <file> <profile>` | Install SCAP content from ZIP | `--force` to reinstall |
| `--enableAll` | Enable all installed benchmarks | Replaced by selective enablement (see below) |
| `--disableAll` | Disable all benchmarks | Run before selective `--enableBenchmark` |
| `--enableBenchmark <id>` | Enable one benchmark by ID | Used for per-host OS scoping |
| `--disableBenchmark <id>` | Disable one benchmark by ID | Alternative to `--disableAll` |
| `--setOpt ignoreCPEOVALResults 1` | Force all benchmarks to run | WS2025 only (no WS2025 benchmark yet) |
| `--setOpt dirXxxEnabled 0` (×7) | Flatten result directory | See playbook for all 7 keys |
| `--listAllBenchmarks` | List installed benchmark IDs | Use for debugging |
| `--applicableToAll <id>` | Force one benchmark applicable | Per-benchmark, less reliable than ignoreCPE |
| `-d` | Debug mode | Creates verbose log |
| `chdir` | **Required** — SCC must run from its own directory | Finds options.xml, Resources/ |

### Key implementation discoveries

1. **`cscc.exe` is Windows-only** — content installation (`--installScap`) must
   run on the Windows target, not on the EE (Linux). The playbook deploys SCC
   first, then installs benchmarks on the target.

2. **`--enableAll` does NOT set `enabled="1"`** in options.xml. SCC uses a
   different internal representation. The XML `allEnabledCount=0` in our
   diagnostic was misleading — content IS enabled, just not via that attribute.
   **[Updated Jul 17]** `--enableAll` remains the pipeline default.
   Selective `--disableAll` + `--enableBenchmark` was attempted but produces
   zero XCCDF results (RC=0, empty output). The enable/disable state does not
   persist across separate `cscc.exe` process invocations. CPE filtering
   handles per-host benchmark selection reliably.

3. **`ignoreCPEOVALResults=1`** is the global "Run All Content" override.
   Required for WS2025 hosts until a WS2025 SCAP benchmark exists. Without it,
   CPE correctly rejects WS2016/2019/2022 benchmarks on WS2025 → zero results.

4. **SCC 5.14 ships with 27 bundled content streams** (IE 11, Defender, .NET,
   Edge, Firewall, Updates, IIS, Chrome, etc.) but NO Windows Server STIG.
   Server benchmarks must be installed separately via `--installScap`.

5. **Host intermittency**: On identical configuration, 1/3 hosts may produce
   zero results (RC 0, empty output dir, no error log). Root cause unconfirmed
   — likely WinRM session timeout or SCC internal failure that returns RC 0.
   **[Updated Jul 17]** Now handled gracefully: Play 1 uses a `rescue` block
   to catch per-host failures (timeout, WinRM errors) without failing the
   entire job. Zero-result hosts get `end_host` (warn + skip). Play 2 uses
   `end_play` when no XCCDF results exist at all (all hosts failed/skipped).

6. **SCC 5.14 checksum is pinned** in the playbook vars (`scc_bundle_checksum`)
   for integrity verification on download.

7. **Network share deployment**: `scc_share_path` variable enables copying SCC
   from a UNC network share (e.g., `\\server\scc`) instead of the default
   80 MB WinRM transfer per host. Significant speedup for large inventories.

8. **`scanner_name` is dead code** (discovered Jul 18). The parameter is declared
   in `normalize_xccdf.py`'s docstring but not in `ARGUMENT_SPEC`. The normalizer
   hardcodes `scanner: 'openscap'` internally and never branches on scanner_name.
   Passing it from the playbook causes "Unsupported parameters" error. Removed
   from `run_scc.yml`.

9. **Jinja2 `regex_search` returns lists, not strings** when capture groups are
   used. `regex_replace` is the only reliable approach for extracting substrings
   in Ansible playbooks. Even `map('regex_search', pattern, '\1')` returns a
   list per item, causing `select('string')` to filter everything out.

10. **EE caching gotcha**: The Controller runs receptor as `ec2-user` (rootless
    podman). Build and push as `ec2-user`, NOT with `sudo`. Use `podman build
    --no-cache` when content changes but image layers cache stale copies.

### Test results (Job 4375, Jul 17 2026)

| Host | XCCDF Files | Windows Server STIG? | Status |
|------|------------|---------------------|--------|
| nm-prod-win202501 | 0 | No | Failed (intermittent) |
| nm-prod-win202502 | 26 | Yes (2022 V2R7 + V2R8) | Success |
| nm-prod-win202503 | 26 | Yes (2022 V2R7 + V2R8) | Success |

Results included: MS_Windows_Server_2022_STIG (2 versions), Windows_Server_2019_STIG
(2 versions), Windows_Server_2016_STIG (2 versions), plus 20 bundled content STIGs.
Normalized: "52 hosts" (26 XCCDF files × 2 hosts).

### Optimization needed

> **[Updated Jul 17]** Selective enablement (`--disableAll` + `--enableBenchmark`)
> was attempted but does NOT produce XCCDF results despite RC=0. The flags
> execute without error but the state does not persist across invocations.
> Pipeline reverted to `--enableAll` + CPE filtering (the proven path).

- **Disable non-Server benchmarks** — `--disableAll` + `--enableBenchmark` was
  implemented and tested across 6 lab runs (jobs 4380–4389) but consistently
  produces zero XCCDF results. SCC's enable/disable state does not persist across
  separate `cscc.exe` process invocations. Future approach: investigate
  `--setOpt` directives or options.xml manipulation to disable specific streams.
- **Check if content already installed** before `--installScap` to skip on re-scans
  of the same target (saves ~30s per host per benchmark).

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
    or github.com/niwc-atlantic/scap-content-library (SCAP 1.4 enhanced)
  → Place in ee/_build/scap-content/ (replaces previous versions)
  → Rebuild EE → push to PAH
  → Next scan installs new content on targets via --installScap automatically
```

### Content Installation (automated, no manual options.xml needed)

SCC 5.14 supports fully programmatic content management:
- `cscc --installScap <zip> MAC-3_Sensitive --force` installs from ZIP
- `cscc --disableAll` then `cscc --enableBenchmark <id>` for selective enablement
  **[Updated Jul 17]** Replaces `--enableAll` for per-host OS scoping
- `cscc --setOpt ignoreCPEOVALResults 1` forces all benchmarks to evaluate (WS2025 only)
- No manual `options.xml` editing or GUI configuration required
- Each scan deploys fresh SCC + installs content on the target — stateless

### Version Tracking

The dashboard should record which benchmark version was used for each scan.
When a benchmark version changes:
- New rules may appear (previously passing hosts now have findings)
- Removed rules drop out of results
- Updated OVAL checks may change pass/fail outcomes
- This is expected behavior, not regression

---

## Remediation Content Strategy (Option C — Jul 18, 2026)

### CaC landscape finding

No Compliance-as-Code standard Windows STIG content exists:

| Source | Windows Coverage | Notes |
|--------|-----------------|-------|
| ComplianceAsCode / SCAP Security Guide (SSG) | **Zero** | Linux/UNIX only. No Windows profiles, roles, or benchmarks. |
| ansible-lockdown | Per-repo (WS2019, WS2022) | Separate repos per version, no multi-version support, no shared data model. |
| DISA supplemental Ansible content | Stale (Feb 2023) | Last update Feb 2023. No WS2025. Not maintained. |
| infra.windows_ops | **275 (WS2022), 216 (WS2019), 248 (WS2025)** | Single role, auto-detection, data-driven task matrices, built-in reporting. |

`infra.windows_ops` is the best available source by a significant margin —
it covers three Windows Server versions in a single collection with
auto-detection logic and data-driven configuration matrices that map
directly to STIG rule IDs.

### Option C (Hybrid) architecture

A generator script (`scripts/generate_rules_metadata.py`) parses
`infra.windows_ops` task files at **build time** and produces rules
metadata YAML per Windows Server version with synthesized Ansible task
previews. A separate `aap_impact_overrides.yml` file provides curated
risk classifications for rules that affect WinRM, firewall, SMB, or
other operational-risk categories.

```
Build-time (generator boundary — no runtime dependency):

  infra.windows_ops/roles/windows_manage_stig/tasks/{version}/*.yml
    → scripts/generate_rules_metadata.py
      → rules/stig_windows_2019.yml  (216 rules + 63 manual)
      → rules/stig_windows_2022.yml  (280 rules + 5 manual)
      → rules/stig_windows_2025.yml  (246 rules + 35 manual)
    + rules/aap_impact_overrides.yml  (~20 curated risk entries)

Runtime (normalizer):
  load_rules_metadata_map() indexes by rule_id (primary) and stig_id (alternate)
  Merge loop falls back to stig_id when rule_id doesn't match
  Dashboard shows "Automation Available" on findings with fix_text
```

The generator is the **decoupling boundary** — it has no runtime
dependency on `infra.windows_ops`. The collection is only needed at
generation time, not at scan time or in the EE.

### Generated output

849 rules across 3 Windows Server versions:

| Version | With fix_text (automationAvailable) | Manual (no fix_text) | Total |
|---------|-------------------------------------|----------------------|-------|
| WS2022 | 280 | 5 | 285 |
| WS2019 | 220 | 63 | 283 |
| WS2025 | 246 | 35 | 281 |

The generator extracts configuration matrices from `infra.windows_ops`
task files (stig_id, title, severity, parameters), maps each category
to the appropriate Ansible module (e.g., `registry_settings` maps to
`win_regedit`, `user_rights_assignment` maps to `win_user_right`), and
synthesizes `fix_text` as Ansible task YAML previews.

### Normalizer change

`load_rules_metadata_map()` now indexes by `stig_id` as an alternate
key in addition to the primary `rule_id` key. The merge loop falls
back to `stig_id` when `rule_id` doesn't match — this handles cases
where XCCDF results use a different rule ID format than the metadata
files.

### Quarterly update workflow

1. DISA publishes new STIG quarterly release
2. Steve's team updates `infra.windows_ops` tasks (adds/removes V-IDs, adjusts params)
3. Steve's team tags a release
4. Dashboard team runs: `python scripts/generate_rules_metadata.py --source <path> --output rules/`
5. Dashboard team reviews diff, updates `aap_impact_overrides.yml` for new risky rules
6. Dashboard team rebuilds EE

**Steve's team maintains `infra.windows_ops` — the dashboard team runs
the generator.** No changes needed in the collection as long as the
`stig_id` field is present in configuration matrices.

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
