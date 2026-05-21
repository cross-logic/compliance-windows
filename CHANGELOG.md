# Changelog

All notable changes to this collection will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-05-21

### Added

- **Backstage Plugin Compatibility**
  - CFF filter plugins now output both camelCase (Backstage) and snake_case (standalone) field names
  - New fields: `stigId`, `fixText`, `checkText`, `disruption`, `parameters` on all CFF outputs
  - Severity mapping: `high` → `CAT_I`, `medium` → `CAT_II`, `low` → `CAT_III`

- **Standard Playbook Entry Points** (for ControllerClient)
  - `playbooks/gather_facts.yml` — gather compliance data from Windows hosts
  - `playbooks/evaluate.yml` — evaluate gathered facts against rule definitions
  - `playbooks/remediate.yml` — apply STIG remediation via windows_ops or PowerSTIG DSC
  - `playbooks/scan.yml` — run PowerSTIG compliance scan
  - `playbooks/normalize.yml` — convert raw results to CFF

- **EE Profile**
  - `meta/ee_profile.yml` — execution environment build profile for STIG scanning

- **Rules**
  - `rules/stig_windows_server_2022.yml` — 10 real DISA STIG V2R1 rules with V-IDs for Windows Server 2022

## [1.0.0] - 2026-05-15

### Added

- **Roles**
  - `compliance_gather` — single WinRM round-trip collection of registry, security policy, audit policy, and service state data
  - `compliance_evaluate` — evaluate gathered facts against YAML rule definitions
  - `normalize_cis_findings` — transform CIS benchmark results to Common Findings Format (CFF)
  - `normalize_stig_findings` — transform DISA STIG results to CFF
  - `normalize_powerstig` — transform PowerSTIG DSC compliance results to CFF
  - `compliance_crosswalk` — map CFF findings to regulatory framework controls (HIPAA, PCI-DSS)

- **Filter Plugins**
  - `to_cff_stig` — convert a single STIG result dict to CFF format
  - `to_cff_cis` — convert a single CIS result dict to CFF format
  - `to_cff_powerstig` — convert a PowerSTIG DSC result to CFF format
  - `map_controls` — annotate CFF findings with regulatory control mappings
  - `crosswalk_summary` — produce per-control compliance summary from findings and a crosswalk profile

- **Compliance Profiles**
  - `hipaa.yml` — maps HIPAA Security Rule § 164.312 technical safeguards to CIS/STIG rule IDs
  - `pci_dss_v4.yml` — maps PCI-DSS v4.0 requirements to CIS/STIG rule IDs
  - Gap controls flagged with notes for requirements without direct technical mappings

- **Playbooks**
  - `scan-windows-cis.yml` — audit-only CIS benchmark scan with CFF output
  - `scan-windows-stig.yml` — audit-only DISA STIG scan with CFF output
  - `scan-windows-hipaa.yml` — CIS scan with HIPAA crosswalk mapping
  - `scan-windows-pci.yml` — CIS scan with PCI-DSS v4.0 crosswalk mapping
  - `verify-windows-cis.yml` — post-remediation CIS verification with threshold assertion
  - `verify-windows-stig.yml` — post-remediation STIG verification with threshold assertion
  - `remediate-windows-cis.yml` — apply CIS benchmark remediation
  - `remediate-windows-stig.yml` — apply DISA STIG remediation

- **Execution Environment Patterns**
  - `compliance-windows-cis` — EE definition for CIS workflows
  - `compliance-windows-stig` — EE definition for STIG workflows

- **CI**
  - GitHub Actions workflow with ansible-lint, ruff, and sanity tests (ansible-core 2.16, 2.17)
  - PSScriptAnalyzer with PSSA-PSCustomUseLiteralPath for PowerShell pslint
  - Auto-merge workflow for owner PRs

- **Infrastructure**
  - Backstage/RHDH catalog-info.yml for developer portal discovery
  - `push_results` shared task for Backstage API and Controller artifact backends
