# DSC on Windows Server — Standalone Scanning Research & Compatibility Notes

This document captures research into DSC (Desired State Configuration) behavior
on standalone (non-domain-joined) Windows Server hosts, specifically when
using PowerSTIG for DISA STIG compliance auditing via Ansible.

**Conclusion**: `Test-DscConfiguration -ReferenceConfiguration` with PowerSTIG
is unsupported on standalone hosts across ALL Windows Server versions
(2016–2025). DISA SCC is the recommended scanner for standalone environments.

## Problem Statement

`Test-DscConfiguration -ReferenceConfiguration $MofFile` fails on standalone
Windows Server hosts with:

```
Could not find mandatory property Thumbprint.
Target: root/Microsoft/Windows/DesiredStateConfiguration:MSFT_DSCLocalConfigurationManager
```

This affects ALL DSC testing cmdlets (`Test-DscConfiguration`,
`Start-DscConfiguration`, `Publish-DscConfiguration`) when processing a
PowerSTIG-compiled MOF.

## Cross-Version Evidence

The error is NOT exclusive to Windows Server 2025. The same class of error has
been reported on all modern Windows Server versions:

| Version | Error | Source |
|---------|-------|--------|
| WS2016 | "mandatory property" errors in DSC | [Ansible-win_dsc #22](https://github.com/trondhindenes/Ansible-win_dsc/issues/22), [SqlServerDsc #11](https://github.com/dsccommunity/SqlServerDsc/issues/11) |
| WS2019 | "Could not find mandatory property Identity" with PowerSTIG | [PowerSTIG #914](https://github.com/microsoft/PowerStig/issues/914) |
| WS2022 | "required property Identity is missing" with PowerSTIG | [PowerSTIG #1262](https://github.com/microsoft/PowerStig/issues/1262) |
| WS2025 | "mandatory property Thumbprint" with PowerSTIG | Our testing (jobs 4286–4335) + [mehic.se](https://mehic.se/2026/02/07/desired-state-configuration-dsc-windows-server-2025-and-rds-2025-nightmare-and-solution/) |

No confirmed success for PowerSTIG + `Test-DscConfiguration -ReferenceConfiguration`
on standalone hosts on ANY version. DSCEA (Microsoft's own audit tool) explicitly
requires Active Directory domain membership.

WS2025 makes it worse with stricter `schema.mof` validation, but the
fundamental issue exists across all versions.

## Root Cause (confirmed Jul 16, 2026)

The error originates from the **LCM (`MSFT_DSCLocalConfigurationManager`)**
when processing credential-related content in the compiled MOF. On standalone
hosts without Active Directory or certificate infrastructure, the DSC engine
cannot validate these properties and fails.

The `NTFSAccessControlEntry` initially suspected as containing a Thumbprint
was a red herring — its schema has no Thumbprint property. The error is from
the LCM's own meta-configuration validation path.

### What was ruled out

Through systematic testing (Controller jobs 4286–4335), we confirmed:

1. **NOT the LCM MetaConfig** — LCM was reset to `RefreshMode: Push`,
   `CertificateID: null`. System-level `MetaConfig.mof` verified clean.
2. **NOT a stale meta.mof** — Compilation output contains ONLY `localhost.mof`
   (304KB). No `localhost.meta.mof` is generated when ConfigurationData omits
   `CertificateFile`/`Thumbprint`.
3. **NOT credential encryption** — PowerSTIG runs as SYSTEM and needs no
   credential encryption. The `PSDscAllowPlainTextPassword = $true` flag
   correctly suppresses meta.mof generation.
4. **NOT the LCM RefreshMode** — `Disabled` blocks `Test-DscConfiguration`
   entirely ("not supported in Disabled mode"). `Push` allows it but hits the
   Thumbprint error from MOF content.

### WS2025 stricter validation

Windows Server 2025 ships with the same WMF 5.1 DSC engine as WS2019/2022,
but has **stricter schema.mof validation**. All write properties declared in
`.schema.mof` files must be implemented. Resources that were tolerated on
older Server versions (with empty or null mandatory properties) now fail
validation.

Sources:
- [WS2025 DSC nightmare (mehic.se)](https://mehic.se/2026/02/07/desired-state-configuration-dsc-windows-server-2025-and-rds-2025-nightmare-and-solution/)
- [DSC v3 migration guide (patchmypc.com)](https://patchmypc.com/blog/desired-state-configuration-v3-explained-what-changed-why-it-matters-and-how-to-migrate/)

## Ansible Collection Analysis

### ansible.windows `win_dsc` module

The `win_dsc` module uses `Invoke-DscResource` directly — it has **zero
certificate handling code** and never touches the LCM or meta.mof. Microsoft
recommends `RefreshMode = 'Disabled'` when using `Invoke-DscResource`
([Issue #128](https://github.com/ansible-collections/ansible.windows/issues/128)).

However, `win_dsc` **blocks composite resources**, which is what PowerSTIG's
`WindowsServer` is. This means `win_dsc` cannot be used directly with
PowerSTIG.

Sources:
- [win_dsc.ps1 source](https://github.com/ansible-collections/ansible.windows/blob/main/plugins/modules/win_dsc.ps1)
- [PR #243: Invoke-DscResource improvements](https://github.com/ansible-collections/ansible.windows/pull/243)

### ansible.windows `dsc3` module (v3.4.0+)

Added in ansible.windows 3.4.0. Uses DSC v3 (`dsc.exe`), which has **no LCM,
no MOF files, no certificates**. Uses YAML/JSON configuration documents.
PowerSTIG does not support DSC v3 natively, but the WindowsPowerShell adapter
may allow v1 resources to be called through the v3 engine.

### community.windows

Contains `win_dsc_*` modules that are wrappers around the same `Invoke-DscResource`
approach. No special certificate handling.

### ansible-lockdown/Windows-2022-STIG

Pure Ansible STIG implementation using standard Windows modules (`win_regedit`,
`win_security_policy`, `win_shell`). No DSC dependency. MIT licensed.
**Limitation**: remediation-only (no audit mode), WS2022 only (no WS2025),
"Check Mode is not supported."

Source: [GitHub](https://github.com/ansible-lockdown/Windows-2022-STIG)

## PowerSTIG Analysis

### Standard workflow (no certs needed)

Per [PowerSTIG DscGettingStarted](https://github.com/microsoft/PowerStig/wiki/DscGettingStarted),
the standard workflow compiles a plain `localhost.mof` with **no
LocalConfigurationManager block, no credentials, no ConfigurationData, no
CertificateFile, and no Thumbprint**. DSC runs as SYSTEM.

### Standalone host support

[Issue #362](https://github.com/microsoft/PowerStig/issues/362) added
workgroup-level scan support in PowerSTIG 4.4.0. The fix allowed simple
hostnames instead of requiring FQDN.

[Issue #718](https://github.com/microsoft/PowerStig/issues/718) documents
non-domain-joined workaround: pass bogus `DomainName` and `ForestName` values
(e.g., `standalone.local`).

### WS2025 support

PowerSTIG 4.30.0 (June 2025) added Windows Server 2025 STIG v1r1 support.
This is a new profile that may not be fully tested for standalone/workgroup
scenarios.

### DoD Root Certificate Rules

The [DoD Root Certificate Rules wiki](https://github.com/microsoft/PowerStig/wiki/DoD-Root-Certificate-Rules)
describes PowerSTIG's handling of DoD certificate thumbprints. These are STIG
compliance rules (checking that specific DoD root CAs are installed), not DSC
credential encryption. These thumbprints appear in the MOF as resource
properties, not in the meta.mof.

### SkipRuleType

PowerSTIG supports skipping entire rule categories:
```powershell
WindowsServer BaseLine {
    OsVersion = '2025'
    OsRole = 'MS'
    SkipRuleType = @('RootCertificateRule', 'UserRightRule')
}
```

`RootCertificateRule` skips DoD root CA checks. `UserRightRule` skips user
rights assignments that require AD. Both confirmed working via DSC warning
output.

## Microsoft DSC Documentation Key Points

### Meta.mof generation

A `localhost.meta.mof` is generated ONLY when a `LocalConfigurationManager`
block is present in the configuration, OR when `ConfigurationData` includes
`CertificateFile`/`Thumbprint`. `PSDscAllowPlainTextPassword = $true` without
cert properties does NOT generate a meta.mof.

Source: [Securing the MOF File](https://learn.microsoft.com/en-us/powershell/dsc/pull-server/securemof)

### Test-DscConfiguration parameter sets

`-ReferenceConfiguration` and `-Detailed` are in **different parameter sets**
and cannot be combined. `-ReferenceConfiguration` returns an object with
`ResourcesInDesiredState` and `ResourcesNotInDesiredState` properties (same
detail as `-Detailed`).

Source: [Test-DscConfiguration Reference](https://learn.microsoft.com/en-us/powershell/module/psdesiredstateconfiguration/test-dscconfiguration)

### Invoke-DscResource (LCM bypass)

`Invoke-DscResource -Method Test` calls each resource's `Test()` method
directly **without going through the LCM pipeline**. No `MetaConfig.mof` is
read, no certificate decryption is needed. However, this requires calling each
resource individually — you cannot test an entire MOF file this way without
parsing and iterating.

Source: [Invoke-DscResource RFC](https://github.com/PowerShell/PowerShell-RFC/blob/master/Archive/Experimental/RFC0047-RFC-Invoke-DscResource.md)

### DSCEA (DSC Environment Analyzer)

Microsoft's own audit tool that uses `Test-DscConfiguration -ReferenceConfiguration`
for compliance auditing without LCM dependency.

Source: [DSCEA documentation](https://microsoft.github.io/DSCEA/mydoc_background.html)

### Remove-DscConfigurationDocument

Can clean up stale LCM state:
```powershell
Remove-DscConfigurationDocument -Stage Current, Pending, Previous -Force
```

Source: [Remove-DscConfigurationDocument](https://learn.microsoft.com/en-us/powershell/module/psdesiredstateconfiguration/remove-dscconfigurationdocument)

## Fix Options

### Option A: SCC as default scanner — SELECTED

**Complexity**: Low | **Confidence**: High

The `run_scc.yml` path already exists with no DSC dependency. SCC has
broader STIG coverage (247/247 vs 206/247 rules), SCAP 1.3 certification,
and works on both standalone and domain-joined hosts. Change `scanner_mode`
default in `install.yml` to `scc`. PowerSTIG becomes opt-in for
domain-joined hosts that specifically need DSC-based scanning.

### Option B: Invoke-DscResource per-resource testing

**Complexity**: High | **Confidence**: High

Parse the compiled MOF and call `Invoke-DscResource -Method Test` for each
resource individually. This completely bypasses the LCM and all certificate
validation. The `ansible.windows` `win_dsc` module uses this exact approach
internally.

Implementation requires:
1. MOF parsing (regex or CIM deserialization)
2. Resource-by-resource `Invoke-DscResource` calls
3. Result aggregation into CFF format

### Option C: Skip cert-bearing rule types

**Complexity**: Medium | **Confidence**: Medium

Add rule types that generate certificate-referencing DSC resources to
`SkipRuleType`. The `NTFSAccessControlEntry` resource with a Thumbprint
reference likely comes from `PermissionRule` in PowerSTIG. This would lose
STIG coverage for those rules.

### Option D: DSC v3 via ansible.windows.dsc3

**Complexity**: Very High | **Confidence**: Low (long-term)

Migrate to DSC v3, which has no LCM, no meta.mof, and no certificate
requirements. Requires installing DSC v3 on targets and porting PowerSTIG
configurations (or using the WindowsPowerShell adapter).

### Option E: Hybrid — compile MOF, test with Ansible modules

**Complexity**: High | **Confidence**: Medium

Compile the MOF on a build host, parse it to determine expected state, then
use standard Ansible modules (`win_regedit`, `win_security_policy`) to check
each setting directly on the target without invoking the DSC engine.

## Key References

| Source | URL |
|--------|-----|
| PowerSTIG Wiki | https://github.com/microsoft/PowerStig/wiki |
| PowerSTIG DscGettingStarted | https://github.com/microsoft/PowerStig/wiki/DscGettingStarted |
| PowerSTIG DoD Root Cert Rules | https://github.com/microsoft/PowerStig/wiki/DoD-Root-Certificate-Rules |
| PowerSTIG Issue #362 (workgroup) | https://github.com/microsoft/PowerStig/issues/362 |
| PowerSTIG Issue #718 (standalone) | https://github.com/microsoft/PowerStig/issues/718 |
| Microsoft DSC securemof | https://learn.microsoft.com/en-us/powershell/dsc/pull-server/securemof |
| Microsoft DSC LCM config | https://learn.microsoft.com/en-us/powershell/dsc/managing-nodes/metaconfig |
| Microsoft Test-DscConfiguration | https://learn.microsoft.com/en-us/powershell/module/psdesiredstateconfiguration/test-dscconfiguration |
| Microsoft Remove-DscConfigurationDocument | https://learn.microsoft.com/en-us/powershell/module/psdesiredstateconfiguration/remove-dscconfigurationdocument |
| Invoke-DscResource RFC | https://github.com/PowerShell/PowerShell-RFC/blob/master/Archive/Experimental/RFC0047-RFC-Invoke-DscResource.md |
| DSCEA | https://microsoft.github.io/DSCEA/mydoc_background.html |
| ansible.windows win_dsc source | https://github.com/ansible-collections/ansible.windows/blob/main/plugins/modules/win_dsc.ps1 |
| ansible.windows Issue #128 | https://github.com/ansible-collections/ansible.windows/issues/128 |
| ansible-lockdown Windows-2022-STIG | https://github.com/ansible-lockdown/Windows-2022-STIG |
| WS2025 DSC breaking changes | https://mehic.se/2026/02/07/desired-state-configuration-dsc-windows-server-2025-and-rds-2025-nightmare-and-solution/ |
| DSC v3 migration guide | https://patchmypc.com/blog/desired-state-configuration-v3-explained-what-changed-why-it-matters-and-how-to-migrate/ |
