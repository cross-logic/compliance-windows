# Crosswalks Guide

This guide explains regulatory control crosswalks in the `security.compliance_windows` collection, covering HIPAA Security Rule and PCI-DSS v4.0 mappings to DISA STIG and CIS Benchmark controls.

## Table of Contents

- [What Are Crosswalks?](#what-are-crosswalks)
- [Crosswalk vs. Scanning](#crosswalk-vs-scanning)
- [Supported Frameworks](#supported-frameworks)
- [How Crosswalks Work](#how-crosswalks-work)
- [Crosswalk File Format](#crosswalk-file-format)
- [Control Status Computation](#control-status-computation)
- [Dashboard Integration](#dashboard-integration)
- [Adding a New Crosswalk](#adding-a-new-crosswalk)
- [Gaps and Unmapped Controls](#gaps-and-unmapped-controls)

## What Are Crosswalks?

A **crosswalk** is a mapping between a regulatory framework (e.g., HIPAA, PCI-DSS) and a technical security standard (e.g., DISA STIG, CIS Benchmark). Crosswalks answer the question:

> "If I pass DISA STIG, what percentage of HIPAA Security Rule requirements am I covered for?"

Crosswalks do not perform scanning. They consume scan results from primary frameworks (STIG, CIS) and map those results to regulatory requirements.

## Crosswalk vs. Scanning

| Feature | Primary Framework (STIG, CIS) | Crosswalk (HIPAA, PCI-DSS) |
|---------|-------------------------------|----------------------------|
| **Scanning** | Yes, executes checks | No, reads existing results |
| **Normalization** | Yes, produces CFF JSON | No, reuses CFF JSON |
| **Dashboard Tab** | First tab (primary findings) | Additional tabs (mapped view) |
| **Control Count** | 366 (STIG), 400+ (CIS) | 12-15 (HIPAA), 20-30 (PCI-DSS) |
| **Remediation** | Direct remediation available | No direct remediation |

A crosswalk is a **read-only view** of compliance data. It does not trigger scans or modify hosts.

## Supported Frameworks

The collection includes two crosswalk profiles:

| Framework | Version | Regulatory Domain | Controls |
|-----------|---------|-------------------|----------|
| **HIPAA Security Rule** | 2013 | Healthcare (ePHI protection) | 12 |
| **PCI-DSS** | v4.0 | Payment card industry | 17 |

### HIPAA Security Rule

Maps to 45 CFR § 164.312 (Technical Safeguards):
- Access Control (164.312(a))
- Audit Controls (164.312(b))
- Integrity (164.312(c))
- Person or Entity Authentication (164.312(d))
- Transmission Security (164.312(e))

### PCI-DSS v4.0

Maps to technical requirements in:
- Requirement 2: Secure Configurations
- Requirement 5: Anti-Malware
- Requirement 8: Access Control
- Requirement 10: Logging and Monitoring
- Requirement 11: Security Testing

## How Crosswalks Work

### Step 1: Primary Scan

Run a DISA STIG or CIS scan as usual:

```bash
ansible-playbook security.compliance_windows.scan-windows-stig -i inventory.yml
```

This produces CFF JSON with 366 STIG findings.

### Step 2: Crosswalk Mapping

The `compliance_crosswalk` role reads the primary scan results and maps them to regulatory controls:

```yaml
- name: Map STIG results to HIPAA
  ansible.builtin.include_role:
    name: security.compliance_windows.compliance_crosswalk
  vars:
    crosswalk_profile: hipaa
    primary_findings: "{{ stig_cff_output }}"
```

The role:
1. Loads `compliance_profiles/hipaa.yml`
2. For each HIPAA control, looks up mapped STIG rules
3. Computes control status from mapped rule statuses
4. Outputs crosswalk CFF JSON

### Step 3: Dashboard Rendering

The crosswalk tab in Ansible Portal displays:
- Control ID and title
- Mapped STIG/CIS rules
- Control status (pass/fail/partial/gap)
- Gap notes for unmapped controls

## Crosswalk File Format

Crosswalks are YAML files in `compliance_profiles/`:

```yaml
# compliance_profiles/hipaa.yml
---
framework: HIPAA
version: "2013"
title: "HIPAA Security Rule — Technical Safeguards"
description: >-
  Maps HIPAA Security Rule technical safeguard requirements (45 CFR § 164.312)
  to CIS Benchmark and DISA STIG controls for Windows Server.

controls:
  - id: "164.312(a)(1)"
    title: "Access Control"
    description: "Implement technical policies and procedures for electronic information systems that maintain ePHI."
    cis_rules:
      - "1.1.1"
      - "1.1.2"
      - "1.1.3"
    stig_rules:
      - "V-254239"
      - "V-254240"
      - "V-254241"

  - id: "164.312(a)(2)(ii)"
    title: "Emergency Access Procedure"
    description: "Establish procedures for obtaining necessary ePHI during an emergency."
    cis_rules: []
    stig_rules: []
    gap: true
    gap_note: "Organizational procedure — no direct technical control."
```

### Required Fields

| Field | Description | Example |
|-------|-------------|---------|
| `framework` | Regulatory framework name | `HIPAA`, `PCI-DSS` |
| `version` | Framework version | `2013`, `v4.0` |
| `title` | Human-readable title | `HIPAA Security Rule — Technical Safeguards` |
| `description` | Framework overview | Multi-line string |
| `controls` | Array of control definitions | See below |

### Control Fields

| Field | Required | Description | Example |
|-------|----------|-------------|---------|
| `id` | Yes | Regulatory control ID | `164.312(a)(1)`, `2.2.1` |
| `title` | Yes | Control title | `Access Control` |
| `description` | Yes | Control description | `Implement technical policies...` |
| `cis_rules` | No | Mapped CIS rule IDs | `["1.1.1", "1.1.2"]` |
| `stig_rules` | No | Mapped STIG vulnerability IDs | `["V-254239", "V-254240"]` |
| `gap` | No | Boolean indicating a gap | `true` |
| `gap_note` | No | Explanation for gap | `Organizational procedure...` |

## Control Status Computation

Control status is computed from mapped rule statuses:

| Condition | Status | Description |
|-----------|--------|-------------|
| All mapped rules passed | **Pass** | Control is satisfied |
| One or more mapped rules failed | **Fail** | Control is not satisfied |
| Some passed, some failed | **Partial** | Control is partially satisfied |
| `gap: true` set | **Gap** | No direct technical control |
| No rules mapped and `gap: false` | **Unmapped** | Mapping incomplete |

### Example: HIPAA 164.312(a)(1) — Access Control

```yaml
- id: "164.312(a)(1)"
  title: "Access Control"
  cis_rules: ["1.1.1", "1.1.2", "1.1.3"]
  stig_rules: ["V-254239", "V-254240"]
```

Primary scan results:
- CIS 1.1.1: **pass**
- CIS 1.1.2: **pass**
- CIS 1.1.3: **fail**
- V-254239: **pass**
- V-254240: **fail**

Control status: **Fail** (at least one mapped rule failed)

### Example: HIPAA 164.312(a)(2)(ii) — Emergency Access

```yaml
- id: "164.312(a)(2)(ii)"
  title: "Emergency Access Procedure"
  cis_rules: []
  stig_rules: []
  gap: true
  gap_note: "Organizational procedure — no direct technical control."
```

Control status: **Gap** (explicitly marked)

## Dashboard Integration

Crosswalks are declared as dashboard tabs in `meta/compliance-profile.yml`:

```yaml
profile:
  display:
    tabs:
      - label: "STIG Findings"
        icon: "security"
        layout:
          - widget: "findings_table"
            title: "STIG Controls"

      - label: "HIPAA Crosswalk"
        icon: "health_and_safety"
        layout:
          - widget: "crosswalk_summary"
            title: "HIPAA Control Coverage"
            crosswalk_profile: "hipaa"
          - widget: "crosswalk_controls_table"
            title: "HIPAA Control Mapping"
            crosswalk_profile: "hipaa"
```

### Crosswalk Widgets

| Widget | Description | Displays |
|--------|-------------|----------|
| `crosswalk_summary` | Control coverage summary | Pass/Fail/Partial/Gap counts, coverage % |
| `crosswalk_controls_table` | Control mapping table | Control ID, title, status, mapped rules |

### Widget Data Source

The `crosswalk_profile` parameter references a file in `compliance_profiles/`:

```yaml
crosswalk_profile: "hipaa"  # Loads compliance_profiles/hipaa.yml
```

## Adding a New Crosswalk

To add a new regulatory framework (e.g., NIST 800-171, GDPR):

### 1. Create Crosswalk YAML

Create `compliance_profiles/<framework>.yml`:

```yaml
---
framework: NIST_800_171
version: "r2"
title: "NIST SP 800-171 — Protecting CUI in Nonfederal Systems"
description: >-
  Maps NIST 800-171 requirements to DISA STIG and CIS Benchmark controls.

controls:
  - id: "3.1.1"
    title: "Limit system access to authorized users"
    description: "..."
    cis_rules: ["1.1.1", "1.1.2"]
    stig_rules: ["V-254239"]

  - id: "3.1.2"
    title: "Limit system access to authorized processes"
    description: "..."
    cis_rules: ["5.1", "5.2"]
    stig_rules: ["V-254386"]
```

### 2. Add Dashboard Tab

Edit `meta/compliance-profile.yml`:

```yaml
profile:
  display:
    tabs:
      # ... existing tabs ...

      - label: "NIST 800-171 Crosswalk"
        icon: "security"
        layout:
          - widget: "crosswalk_summary"
            title: "NIST 800-171 Control Coverage"
            crosswalk_profile: "nist_800_171"
          - widget: "crosswalk_controls_table"
            title: "NIST 800-171 Control Mapping"
            crosswalk_profile: "nist_800_171"
```

### 3. Add Crosswalk Playbook

Create `playbooks/scan-windows-nist.yml`:

```yaml
---
- name: "Scan Windows Server NIST 800-171 compliance (crosswalk view)"
  hosts: "{{ compliance_target_hosts | default('windows') }}"
  gather_facts: true

  tasks:
    # Run primary STIG scan
    - name: Run STIG scan
      ansible.builtin.include_tasks:
        file: scan-windows-stig.yml

    # Map STIG results to NIST 800-171
    - name: Map to NIST 800-171
      ansible.builtin.include_role:
        name: compliance_crosswalk
      vars:
        crosswalk_profile: nist_800_171
        primary_findings: "{{ stig_cff_output }}"
```

### 4. Update Documentation

Update README.md to list the new crosswalk in the Supported Frameworks table.

## Gaps and Unmapped Controls

Not all regulatory requirements map directly to technical controls. Examples:

### HIPAA Gaps

**164.312(a)(2)(ii) — Emergency Access Procedure**
- **Gap note**: "Organizational procedure — no direct technical control."
- **Why**: HIPAA requires documented emergency access procedures, which are policy-driven and not enforced by Windows registry/GPO.

### PCI-DSS Gaps

**10.5.1 — Retain Audit Logs 12 Months**
- **Gap note**: "Log retention is typically enforced by a central log management system, not local Windows policy."
- **Why**: PCI-DSS requires 12-month audit log retention, which exceeds Windows Event Log capacity and requires SIEM/log aggregation.

**11.5.2 — File Integrity Monitoring**
- **Gap note**: "FIM requires a dedicated agent (AIDE, Tripwire, Wazuh). No native Windows GPO control."
- **Why**: PCI-DSS requires FIM on critical system files, which is not provided by Windows Server natively.

### Marking Gaps

Set `gap: true` and provide a `gap_note`:

```yaml
- id: "10.5.1"
  title: "Retain Audit Logs 12 Months"
  cis_rules: []
  stig_rules: []
  gap: true
  gap_note: "Log retention is typically enforced by a central log management system, not local Windows policy."
```

The dashboard renders gaps with a distinct status (e.g., yellow warning icon) and displays the gap note in a tooltip.
