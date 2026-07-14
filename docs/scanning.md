# Scanning Guide

This guide explains how compliance scanning works in the `security.compliance_windows` collection, covering scanner backends, SCAP content distribution, output formats, and normalization requirements.

## Table of Contents

- [Scanner Backends](#scanner-backends)
- [DISA SCC Scanner](#disa-scc-scanner)
- [infra.windows_ops Scanner](#infrawindows_ops-scanner)
- [PowerSTIG Scanner](#powerstig-scanner)
- [SCAP Benchmark Content](#scap-benchmark-content)
- [Output Formats](#output-formats)
- [Normalization Requirements](#normalization-requirements)
- [Scan Workflow](#scan-workflow)

## Scanner Backends

The collection supports three scanner backends, selected via the `compliance_scanner` variable:

| Scanner | Value | Certification | Use Case |
|---------|-------|---------------|----------|
| DISA SCC | `scc` (default) | SCAP 1.3 Certified | DoD/FedRAMP STIG compliance |
| infra.windows_ops | `ansible` | Conformant | CIS hardening checks |
| PowerSTIG | `powerstig` | Uncertified | DSC-native STIG scanning |

Set the scanner in playbook extra_vars or Controller JT variables:

```yaml
- name: Scan with specific scanner
  hosts: windows
  vars:
    compliance_scanner: scc  # or 'ansible' or 'powerstig'
```

## DISA SCC Scanner

**DISA SCAP Compliance Checker (SCC)** is NIST SCAP 1.3 validated and produces certified STIG assessment results accepted by DoD and FedRAMP auditors.

### How It Works

1. **Download SCC**: The scanner is downloaded ephemerally from `dl.dod.cyber.mil` at scan time due to NIWC trade secret licensing restrictions. The collection includes a download role that caches SCC in `/tmp/disa-scc/` on the execution node.

2. **Transfer to targets**: SCC binaries are copied to each Windows target (via SSH or WinRM).

3. **Copy SCAP content**: XCCDF datastreams are copied from the execution environment to each target.

4. **Run scan**: SCC runs as a CLI tool on each target, consuming the XCCDF datastream and producing XCCDF result XML.

5. **Fetch results**: Result XML files are fetched back to the execution node.

6. **Normalize**: The `normalize_stig_findings` role parses XCCDF XML and outputs CFF JSON.

7. **Cleanup**: SCC binaries and SCAP content are removed from targets.

### SCC Ephemeral Download Pattern

SCC is downloaded once per scan job and cached in the execution node's `/tmp/disa-scc/` directory. If a cached copy exists and is less than 7 days old, it is reused. Otherwise, a fresh copy is downloaded.

```yaml
- name: Download DISA SCC (ephemeral)
  ansible.builtin.get_url:
    url: https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/scc-latest.zip
    dest: /tmp/disa-scc/scc-latest.zip
    mode: '0644'
  delegate_to: localhost
  run_once: true
  when: >
    not ansible_check_mode and
    (not scc_cache_stat.stat.exists or
     (ansible_date_time.epoch | int) - scc_cache_stat.stat.mtime > 604800)
```

This pattern ensures:
- No SCC binaries embedded in the EE (licensing compliance)
- Minimal network overhead (download once per job, not per host)
- Cache invalidation (fresh copy every 7 days)

### SCC Output Format

SCC produces XCCDF 1.2 result XML:

```xml
<xccdf:TestResult>
  <xccdf:rule-result idref="xccdf_mil.disa.stig_rule_V-254239" time="2025-01-15T10:30:00" severity="high">
    <xccdf:result>fail</xccdf:result>
    <xccdf:ident system="http://cyber.mil/legacy">V-254239</xccdf:ident>
    <xccdf:check system="http://oval.mitre.org/XMLSchema/oval-definitions-5">
      <xccdf:check-content-ref href="U_MS_Windows_Server_2022_STIG_V2R7_OVAL.xml" name="oval:mil.disa.stig.windows:def:1000" />
    </xccdf:check>
  </xccdf:rule-result>
</xccdf:TestResult>
```

## infra.windows_ops Scanner

The **infra.windows_ops** collection provides Ansible-native CIS hardening checks via the `windows_manage_cis` role. Results are conformant with CIS benchmarks but not CIS-certified.

### How It Works

1. **Execute tasks**: The `windows_manage_cis` role runs Ansible tasks on each Windows target, checking registry keys, policies, and services.

2. **Collect results**: Results are returned as structured facts in `windows_manage_cis_results`.

3. **Normalize**: The `normalize_cis_findings` role transforms results to CFF JSON.

### infra.windows_ops Output Format

The scanner returns a dict of findings:

```yaml
windows_manage_cis_results:
  - rule_id: "1.1.1"
    title: "Ensure 'Enforce password history' is set to '24 or more password(s)'"
    status: "pass"
    severity: "medium"
    actual_value: "24"
    expected_value: "24"
    check_type: "registry"
  - rule_id: "1.1.2"
    title: "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'"
    status: "fail"
    severity: "medium"
    actual_value: "0"
    expected_value: "365"
    check_type: "registry"
```

This format is normalized to CFF by `normalize_cis_findings`.

## PowerSTIG Scanner

**PowerSTIG** is a DSC-native STIG scanner using PowerShell Desired State Configuration modules. It is uncertified but useful for environments standardized on DSC.

### How It Works

1. **Install PowerSTIG**: The `normalize_powerstig` role installs PowerSTIG modules on targets via PowerShell Gallery.

2. **Run DSC scan**: PowerSTIG compiles and applies a DSC configuration in audit mode.

3. **Parse DSC output**: PowerSTIG produces a compliance report in JSON format.

4. **Normalize**: The role transforms PowerSTIG JSON to CFF.

### PowerSTIG Output Format

PowerSTIG returns a JSON array of findings:

```json
[
  {
    "VulnId": "V-254239",
    "RuleId": "SV-254239r958412_rule",
    "Severity": "CAT II",
    "Title": "The password history must be configured to 24 passwords remembered.",
    "Status": "Open",
    "ActualValue": "12",
    "ExpectedValue": "24"
  }
]
```

## SCAP Benchmark Content

SCAP benchmark content (XCCDF datastreams) is **freely redistributable** under DoD/DISA licensing. Datastreams are included in the execution environment and copied to targets at scan time.

### SCAP Content Location

EE path: `/usr/share/xml/scap/disa/stig/`

Content files:
- `U_MS_Windows_Server_2019_STIG_V3R2_XCCDF.xml`
- `U_MS_Windows_Server_2022_STIG_V2R7_XCCDF.xml`
- `U_MS_Windows_Server_2025_STIG_V1R1_XCCDF.xml`

Each datastream contains:
- Rule definitions (title, description, severity, fix_text)
- OVAL checks (registry keys, file permissions, service states)
- CCI references (NIST 800-53 control mappings)

### Datastream Size

Each datastream is approximately 5-8 MB compressed, 15-25 MB uncompressed. Copying datastreams to targets adds ~10 seconds to scan time for a 10-host inventory.

## Output Formats

All scanners normalize to **Common Findings Format (CFF)**, a standardized JSON schema for compliance results:

```json
{
  "scan_id": "scan-20250115-103000",
  "framework": "DISA_STIG",
  "version": "V2R7",
  "scanner": "scc",
  "certification_status": "certified",
  "findings": [
    {
      "rule_id": "V-254239",
      "title": "The password history must be configured to 24 passwords remembered.",
      "description": "...",
      "severity": "CAT_II",
      "status": "fail",
      "host": "win-server-01",
      "actual_value": "12",
      "expected_value": "24",
      "fix_text": "Set GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Account Policies > Password Policy > Enforce password history = 24",
      "stig_id": "V-254239",
      "cci": ["CCI-000200"]
    }
  ],
  "summary": {
    "total": 366,
    "pass": 298,
    "fail": 68,
    "not_applicable": 0
  }
}
```

## Normalization Requirements

Per ADR-030, all normalizer playbooks **MUST loop per-host** to prevent out-of-memory errors on execution nodes:

```yaml
- name: Normalize findings per host
  ansible.builtin.include_role:
    name: normalize_stig_findings
  loop: "{{ groups['windows'] }}"
  loop_control:
    loop_var: target_host
```

This ensures:
- Memory usage scales linearly with host count (not O(n²))
- Large inventories (100+ hosts) do not exhaust execution node RAM
- Failed hosts do not block processing of successful hosts

### Memory Footprint

Per-host normalization limits memory to:
- XCCDF parsing: ~50 MB per host (XML DOM parsing)
- CFF output: ~2-5 MB per host (366 findings × ~8 KB each)
- Total: ~55 MB per host

A 100-host scan consumes ~5.5 GB RAM on the execution node when run serially per-host, compared to 50+ GB if all hosts are processed in parallel.

## Scan Workflow

The full scan workflow for DISA STIG with SCC:

```
┌───────────────────────────────────────────────────────────────────────┐
│ Play 1: Scan targets (runs on Windows hosts)                         │
├───────────────────────────────────────────────────────────────────────┤
│ 1. Download SCC from dl.dod.cyber.mil (once per job, cached)         │
│ 2. Copy SCC binaries to each target (via WinRM)                      │
│ 3. Copy SCAP datastream from EE to each target                       │
│ 4. Run SCC on each target (oscap xccdf eval)                         │
│ 5. Fetch XCCDF result XML back to execution node                     │
│ 6. Cleanup SCC binaries and SCAP content from targets                │
└───────────────────────────────────────────────────────────────────────┘
                                ↓
┌───────────────────────────────────────────────────────────────────────┐
│ Play 2: Normalize results (runs on localhost)                        │
├───────────────────────────────────────────────────────────────────────┤
│ 1. Parse XCCDF XML per host (loop to prevent OOM)                    │
│ 2. Extract rule metadata from datastream                             │
│ 3. Map XCCDF IDs to STIG vulnerability IDs                           │
│ 4. Transform to CFF JSON                                             │
│ 5. Write compliance_report.json to execution node                    │
└───────────────────────────────────────────────────────────────────────┘
                                ↓
┌───────────────────────────────────────────────────────────────────────┐
│ Play 3: Push results (runs on localhost)                             │
├───────────────────────────────────────────────────────────────────────┤
│ 1. POST CFF JSON to Ansible Portal compliance backend                │
│ 2. Include per-scan security token (ADR-010)                         │
│ 3. Log summary to Controller job output                              │
└───────────────────────────────────────────────────────────────────────┘
```

The workflow is identical for CIS scanning, except:
- Step 1: No SCC download (infra.windows_ops is embedded)
- Step 4: Run `windows_manage_cis` role instead of SCC
- Step 5: Fetch structured dict instead of XCCDF XML
- Play 2: Use `normalize_cis_findings` instead of `normalize_stig_findings`
