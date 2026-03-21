# DES/RC4 Kerberos Encryption Assessment

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![Version](https://img.shields.io/badge/version-2.3.0-orange)

> **📌 Note:** Legacy v1.0 files are archived in the [`archive/`](archive/) folder for reference.

A PowerShell toolkit for assessing DES and RC4 Kerberos encryption usage in Active Directory — with inline remediation commands, event log analysis, KDC registry checks, and forest-wide scanning. Built for the **July 2026 RC4 removal deadline**.

## Why This Toolkit?

Microsoft will **completely remove RC4 from the Kerberos KDC path in July 2026**. After that date, only accounts with _explicit_ RC4 in `msDS-SupportedEncryptionTypes` will work with RC4. Everything else gets blocked.

This toolkit helps you:
- **Discover** all RC4/DES usage across your forest in minutes (not hours)
- **Get fix commands** shown inline with every finding — copy-paste ready
- **Track progress** by comparing assessments over time
- **Prepare** for the January 2026 and July 2026 milestones

## Key Features

| Feature | Description |
|---------|-------------|
| **DC Encryption Check** | Scans all DCs for `msDS-SupportedEncryptionTypes` and GPO Kerberos policy |
| **Trust Assessment** | Post-Nov 2022 logic: trusts default to AES when attribute is not set |
| **KDC Registry Check** | Reads `DefaultDomainSupportedEncTypes` and `RC4DefaultDisablementPhase` from all DCs |
| **Audit Policy Verification** | Checks if Kerberos auditing (4768/4769) is enabled before event log analysis |
| **Event Log Analysis** | Queries events 4768/4769 from all DCs to find actual RC4/DES ticket usage |
| **KRBTGT Assessment** | Password age, encryption types, rotation guidance |
| **Service Account Scan** | SPN accounts, gMSA/sMSA with RC4/DES-only encryption |
| **USE_DES_KEY_ONLY Detection** | Accounts with the UserAccountControl flag forcing DES |
| **Missing AES Keys** | Accounts with passwords predating DFL 2008 raise (no AES keys generated) |
| **Stale Password Detection** | Service accounts with passwords >365 days old and RC4 enabled |
| **Inline Fix Commands** | Every finding includes copy-paste PowerShell remediation commands |
| **Forest-Wide Scanning** | Assess all domains in a forest with parallel processing (PS 7+) |
| **Compare Over Time** | Track remediation progress between two assessment exports |
| **Full Reference Manual** | `-IncludeGuidance` shows audit setup, SIEM queries, KRBTGT rotation, July 2026 timeline |

## Quick Start

```powershell
# Prerequisites
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0

# Quick scan (config only, ~30 seconds)
.\RC4_DES_Assessment.ps1 -QuickScan

# Full scan with event logs (~3-5 minutes)
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168

# Full scan + export + reference manual
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults -IncludeGuidance

# Entire forest (parallel, PS 7+)
.\Assess-ADForest.ps1 -AnalyzeEventLogs -ExportResults -Parallel -MaxParallelDomains 5

# Compare two runs
.\Compare-Assessments.ps1 -BaselineFile before.json -CurrentFile after.json -ShowDetails
```

## Prerequisites

- **PowerShell:** 5.1+ (7+ for parallel forest assessment)
- **Modules:** `ActiveDirectory`, `GroupPolicy`
- **Permissions:** Domain Admin or equivalent (Event Log Readers for event analysis)
- **Network:** WinRM (5985) or RPC (135) to DCs for event log and registry queries

## Scripts

| Script | Purpose |
|--------|---------|
| `RC4_DES_Assessment.ps1` | Main assessment tool (v2.3.0) |
| `Assess-ADForest.ps1` | Forest-wide wrapper — runs assessment per domain |
| `Compare-Assessments.ps1` | Compare two JSON exports to track progress (v2.3.0) |
| `Test-EventLogFailureHandling.ps1` | Test script for event log error handling |
| `Tests/` | 161 Pester unit tests |

## Parameters

### RC4_DES_Assessment.ps1

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Domain` | Target domain | Current domain |
| `-Server` | Specific DC to query | Auto-discovered |
| `-AnalyzeEventLogs` | Analyze events 4768/4769 for actual RC4/DES usage | Off |
| `-EventLogHours` | Hours of events to analyze (1-168) | 24 |
| `-ExportResults` | Export to JSON + CSV in `.\Exports\` | Off |
| `-IncludeGuidance` | Show full reference manual (audit setup, SIEM queries, KRBTGT rotation, July 2026 timeline) | Off |
| `-QuickScan` | Config-only scan (no event logs) | Default mode |

### Assess-ADForest.ps1

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-ForestName` | Target forest | Current forest |
| `-AnalyzeEventLogs` | Include event log analysis per domain | Off |
| `-EventLogHours` | Hours of events (1-168) | 24 |
| `-ExportResults` | Export per-domain + forest summary | Off |
| `-Parallel` | Process domains concurrently (PS 7+) | Off |
| `-MaxParallelDomains` | Max concurrent domains (1-10) | 3 |

## Sample Output

### Quick Scan — Warnings with Inline Fixes

```
================================================================================
DES/RC4 Kerberos Encryption Assessment v2.3.0
================================================================================

Domain Controller Encryption Configuration
────────────────────────────────────────────────────────────────
ℹ️  Found 1 Domain Controller(s)
✅ All Domain Controllers have AES encryption configured
⚠️  1 DC(s) have RC4 encryption enabled

KRBTGT & Service Account Encryption Assessment
────────────────────────────────────────────────────────────────
✅ KRBTGT password age: 21 days
✅ No accounts with USE_DES_KEY_ONLY flag
✅ No service accounts with RC4/DES-only encryption
✅ No accounts found with potentially missing AES keys

KDC Registry Configuration Assessment
────────────────────────────────────────────────────────────────
ℹ️  DefaultDomainSupportedEncTypes: Not set (uses OS defaults)
⚠️  RC4DefaultDisablementPhase not set
   Deploy January 2026+ security updates and set to 1 on all DCs

Overall Security Assessment
────────────────────────────────────────────────────────────────
⚠️  Security warnings detected - remediation recommended

  Recommendations & Remediation:
    • WARNING: [contoso.com] Remove RC4 encryption from 1 Domain Controller(s): DC01
      # Or configure via GPO: 'Network security: Configure encryption types
      #   allowed for Kerberos' = AES128 + AES256
      PS> Set-ADComputer DC01 -Replace @{'msDS-SupportedEncryptionTypes'=24}

    • WARNING: [contoso.com] RC4DefaultDisablementPhase not set
      # Deploy January 2026+ security updates, then on each DC:
      PS> Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
            -Name 'RC4DefaultDisablementPhase' -Value 1 -Type DWord
      # This disables RC4 for accounts without explicit RC4 in
      #   msDS-SupportedEncryptionTypes

  💡 Tip: Use -IncludeGuidance for the full reference manual
     (audit setup, SIEM queries, KRBTGT rotation, July 2026 timeline).

📊 Summary:
  • Domain: contoso.com
  • Overall Status: WARNING
```

### Full Scan — RC4 Detected in Event Logs

```
Kerberos Audit Policy Verification
────────────────────────────────────────────────────────────────
✅ Kerberos auditing is enabled (Authentication Service + Ticket Operations)

Event Log Analysis - Actual DES/RC4 Usage
────────────────────────────────────────────────────────────────
ℹ️  Querying event logs from 3 Domain Controller(s)...
  • DC01... ✅ 12,543 events
  • DC02... ✅ 11,892 events
  • DC03... ❌ RPC server unavailable

❌ RC4 tickets detected in active use!
  RC4 accounts: LEGACY-APP$, SQL2008-SRV$

  Recommendations & Remediation:
    • CRITICAL: [contoso.com] RC4 tickets detected (8 tickets,
        accounts: LEGACY-APP$, SQL2008-SRV$)
      # For each account using RC4, try AES first:
      PS> Set-ADUser '<AccountName>' -Replace @{
            'msDS-SupportedEncryptionTypes'=24}
      PS> Set-ADAccountPassword '<AccountName>' -Reset; klist purge
      # If AES fails, add explicit RC4 exception:
      #   -Replace @{'msDS-SupportedEncryptionTypes'=0x1C}
```

## Recommended Workflow

```
Phase 1: Discovery                    Phase 2: Deep Analysis
.\RC4_DES_Assessment.ps1              .\RC4_DES_Assessment.ps1 `
    -QuickScan                            -AnalyzeEventLogs `
                                          -EventLogHours 168 `
         │                                -ExportResults
         ├── ✅ All OK → Monitor          
         └── ⚠ Issues → ─────────────────────┘
                                               │
Phase 3: Remediate                    Phase 4: Validate
Follow inline fix commands            .\RC4_DES_Assessment.ps1 `
  • Set-ADComputer for DCs                -AnalyzeEventLogs -ExportResults
  • Set RC4DefaultDisablementPhase    .\Compare-Assessments.ps1 `
  • Reset service account passwords       -BaselineFile before.json `
  • klist purge after changes             -CurrentFile after.json -ShowDetails
         │                                     │
         └─── Repeat until OK ────────────────┘
                    │
         Ready for July 2026 RC4 removal
```

## July 2026 RC4 Removal Timeline

| Date | Milestone | Action |
|------|-----------|--------|
| **Nov 2022** | Post-OOB updates change trust/computer defaults to AES | Trusts with unset `msDS-SupportedEncryptionTypes` now default to AES |
| **Jan 2026** | Security updates add `RC4DefaultDisablementPhase` registry key | Set to `1` on all DCs to begin RC4 disablement |
| **Jul 2026** | RC4 completely removed from KDC path | Only accounts with _explicit_ RC4 in `msDS-SupportedEncryptionTypes` will work |

### What Happens After July 2026

- Accounts **without** `msDS-SupportedEncryptionTypes` set → use AES (secure, no action needed)
- Accounts with AES in `msDS-SupportedEncryptionTypes` → use AES (secure)
- Accounts with **explicit RC4** (`0x4` bit) in `msDS-SupportedEncryptionTypes` → still allowed (exception)
- Accounts relying on default/legacy RC4 fallback → **blocked**

### Explicit RC4 Exception (Last Resort)

If a service absolutely cannot use AES after July 2026:

```powershell
# User/service account:
Set-ADUser 'svc_LegacyApp' -Replace @{'msDS-SupportedEncryptionTypes'=0x1C}
# 0x1C = RC4 + AES128 + AES256
Set-ADAccountPassword 'svc_LegacyApp' -Reset; klist purge

# Computer account (rare):
Set-ADComputer 'LEGACYHOST' -Replace @{'msDS-SupportedEncryptionTypes'=0x1C}
klist purge

# Ensure DCs still allow explicit RC4:
# DefaultDomainSupportedEncTypes must include 0x4 (RC4) if you have any exceptions
```

Document all exceptions and plan vendor upgrades.

## Post-November 2022 Logic

### Computer Objects
RC4 fallback only occurs when **both** conditions are true:
1. `msDS-SupportedEncryptionTypes` on the client is set to a non-zero value
2. `msDS-SupportedEncryptionTypes` on the DC does NOT include AES

**Impact:** You do NOT need to set this attribute on 100,000+ computers if DCs have AES configured via GPO.

### Trusts
When `msDS-SupportedEncryptionTypes` is 0 or empty on trusts, they **default to AES**. No action needed for these trusts.

## Compare-Assessments

Track remediation progress by comparing two exported JSON files:

```powershell
.\Compare-Assessments.ps1 -BaselineFile week1.json -CurrentFile week2.json -ShowDetails
```

Compares:
- DC encryption changes (AES/RC4/DES counts)
- Trust risk changes
- Account changes (KRBTGT status, DES flags, RC4-only service accounts, missing AES keys)
- KDC registry changes (`RC4DefaultDisablementPhase` value)
- Event log ticket changes (RC4/DES ticket counts)

## Export Format

Results are exported to `.\Exports\` as JSON (full data) and CSV (summary table).

```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults
# Creates:
#   Exports\DES_RC4_Assessment_contoso_com_20260321_143015.json
#   Exports\DES_RC4_Assessment_contoso_com_20260321_143015.csv
```

The JSON export includes all assessment data: DCs, trusts, accounts (KRBTGT, service accounts, DES flags, missing AES keys), KDC registry, event logs, and recommendations with fix commands.

## Troubleshooting

### Event Log Access
When event log queries fail, the script shows detailed troubleshooting:
- **WinRM not available:** `Enable-PSRemoting -Force` on each DC
- **RPC blocked:** Enable firewall rule `Remote Event Log Management`
- **Access denied:** Add account to `Event Log Readers` group
- **Network unreachable:** Use `-Server` parameter or run script locally on DC

### Child Domain Access
```powershell
# If auto-discovery fails, specify a DC directly:
.\RC4_DES_Assessment.ps1 -Server DC01.child.contoso.com -AnalyzeEventLogs
```

### No Events Found
Verify Kerberos auditing is enabled (the script checks this automatically with `-AnalyzeEventLogs`):
```powershell
auditpol /get /subcategory:"Kerberos Authentication Service"
auditpol /get /subcategory:"Kerberos Service Ticket Operations"
```

## Reference Documentation

- [KB5021131: Managing Kerberos protocol changes](https://support.microsoft.com/kb/5021131)
- [What happened to Kerberos after November 2022 updates](https://techcommunity.microsoft.com/blog/askds/what-happened-to-kerberos-authentication-after-installing-the-november-2022oob-u/3696351)
- [Decrypting Kerberos Encryption Types Selection](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/decrypting-the-selection-of-supported-kerberos-encryption-types/1628797)
- [Detect and Remediate RC4 Usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-rc4)
- [Microsoft Kerberos-Crypto Scripts](https://github.com/microsoft/Kerberos-Crypto) (Get-KerbEncryptionUsage.ps1, List-AccountKeys.ps1)

## Version History

### v2.3.0 (March 2026) — Current
- KDC registry assessment (`DefaultDomainSupportedEncTypes`, `RC4DefaultDisablementPhase`)
- Kerberos audit policy pre-check before event log analysis
- Missing AES keys detection (accounts with passwords predating DFL 2008)
- Inline remediation commands shown with every finding (no switch needed)
- July 2026 RC4 removal timeline and January 2026 update guidance
- Explicit RC4 exception workflow for user and computer accounts
- `klist purge` in all remediation steps
- Compare-Assessments.ps1: account changes, registry keys, missing AES keys
- Microsoft Kerberos-Crypto tools references

### v2.2.0 (February 2026)
- KRBTGT password age and encryption type assessment
- USE_DES_KEY_ONLY flag detection
- Service account (SPN) RC4/DES-only encryption detection
- gMSA/sMSA encryption review
- Stale password service account detection (>365 days with RC4)

### v2.1.0 (December 2025)
- WinRM-first event log queries with RPC fallback
- Full forest DC enumeration per domain
- Child domain support fixes
- Comprehensive summary tables

### v2.0.0 (October 2025)
- Complete rewrite with post-November 2022 logic
- Fast execution (< 5 minutes vs 5+ hours in v1.0)
- Event-based actual usage detection

## License

MIT — See [LICENSE](LICENSE) file.

## Credits

- Author: Jan Tiedemann
- Customer feedback and real-world testing (Thanks to Simon Arnreiter)
- Microsoft Kerberos security documentation team
