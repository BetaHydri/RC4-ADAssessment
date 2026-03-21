# RC4_DES_Assessment.ps1 v2.3.0 - Quick Start Guide

> **✨ New in v2.3.0:** KDC registry assessment, Kerberos audit policy pre-check, missing AES keys detection, inline remediation commands with every finding, and July 2026 RC4 removal timeline guidance. See also v2.2.0: KRBTGT assessment, service account scan, USE_DES_KEY_ONLY detection, stale password detection.

## 🔐 Using with Active Directory

### Prerequisites
- PowerShell 5.1 or later (7+ for parallel forest assessment)
- Active Directory PowerShell module (`RSAT-AD-PowerShell`)
- Group Policy PowerShell module (`GPMC`)
- Domain Admin or equivalent permissions
- Network access to domain controllers (WinRM 5985 or RPC 135)

### Quick Scan (Fastest - No Event Logs)
```powershell
.\RC4_DES_Assessment.ps1 -QuickScan
```
**Runtime**: ~30 seconds  
**Checks**: DCs, GPOs, Trusts, KRBTGT, Service Accounts, KDC Registry, DES flags, Missing AES keys

### Full Assessment (Recommended)
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 24
```
**Runtime**: 2-5 minutes  
**Checks**: All of the above + audit policy verification + 24 hours of event logs for actual DES/RC4 usage

### With Export
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults
```
**Output**: JSON and CSV files with timestamp in `.\Exports\`

### With Full Reference Manual
```powershell
.\RC4_DES_Assessment.ps1 -IncludeGuidance
```
**Shows**: Audit setup, SIEM/Splunk queries, KRBTGT rotation guidance, July 2026 timeline

### Specific Domain
```powershell
.\RC4_DES_Assessment.ps1 -Domain contoso.com -AnalyzeEventLogs
```

### Forest-Wide Assessment
```powershell
# Quick scan all domains in forest
.\Assess-ADForest.ps1

# Full assessment with event logs
.\Assess-ADForest.ps1 -AnalyzeEventLogs -ExportResults

# Parallel processing (PowerShell 7+)
.\Assess-ADForest.ps1 -Parallel -MaxParallelDomains 5 -AnalyzeEventLogs
```
**Runtime**: Varies (parallel mode processes multiple domains concurrently)  
**Output**: Per-domain JSON exports + forest-wide summary

### Compare Two Runs (Track Progress)
```powershell
.\Compare-Assessments.ps1 -BaselineFile before.json -CurrentFile after.json -ShowDetails
```
**Compares**: DC encryption, trusts, accounts (KRBTGT, service accounts, DES flags, missing AES keys), KDC registry, event log tickets

---

## 📊 Sample Output

### Successful Quick Scan
```
================================================================================
DES/RC4 Kerberos Encryption Assessment v2.3.0
================================================================================

Domain Controller Encryption Configuration
────────────────────────────────────────────────────────────────
ℹ️  Found 3 Domain Controller(s)
✅ All Domain Controllers have AES encryption configured

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

Trust Encryption Assessment (Post-November 2022 Logic)
────────────────────────────────────────────────────────────────
ℹ️  Found 1 trust(s)
✅ Trust 'partner.com': Uses AES by default (msDS-SupportedEncryptionTypes not set)

Overall Security Assessment
────────────────────────────────────────────────────────────────
⚠️  Security warnings detected - remediation recommended

  Recommendations & Remediation:
    • WARNING: [contoso.com] RC4DefaultDisablementPhase not set
      # Deploy January 2026+ security updates, then on each DC:
      PS> Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
            -Name 'RC4DefaultDisablementPhase' -Value 1 -Type DWord

  💡 Tip: Use -IncludeGuidance for the full reference manual
```

### Event Log Analysis with RC4 Detection
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

### Event Log Access Failures (NEW in v2.0.1)
```
  ⚠  Event Log Query Failures:
  2 Domain Controller(s) could not be queried for event logs

  • DC01.contoso.com: The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)
  • DC03.contoso.com: Access is denied. Attempted to perform an unauthorized operation.

  🔧 How to fix remote event log access issues:

  Option 1: Enable WinRM (Recommended)
  ────────────────────────────────────────
  Run on each failed DC:
  PS> Enable-PSRemoting -Force
  PS> Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force
  PS> Restart-Service WinRM

  Option 2: Configure Firewall for RPC
  ────────────────────────────────────────
  Required ports:
  - TCP 135 (RPC Endpoint Mapper)
  - TCP 49152-65535 (Dynamic RPC ports)

  Windows Firewall rule:
  PS> Enable-NetFirewallRule -DisplayGroup 'Remote Event Log Management'

  Option 3: Run Locally on DC
  ────────────────────────────────────────
  Copy script to DC and run:
  PS> .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 24

  Option 4: Verify Permissions
  ────────────────────────────────────────
  Add your account to 'Event Log Readers' group on DCs:
  PS> Add-ADGroupMember -Identity 'Event Log Readers' -Members 'YourAccount'
```

### Summary Tables (NEW in v2.1.0)

At the end of every assessment, you'll see comprehensive summary tables:

```
Assessment Summary Tables
────────────────────────────────────────────────────────────────

  DOMAIN CONTROLLER SUMMARY
  ────────────────────────────────────────────────────────────────
  
  Domain Controller  Status   Encryption Types       GPO Status  Operating System
  -----------------  ------   ----------------       ----------  ----------------
  DC01.contoso.com   OK       AES128-HMAC, AES256    OK          Windows Server 2022
  DC02.contoso.com   WARNING  RC4-HMAC, AES128       WARNING     Windows Server 2019
  DC03.contoso.com   CRITICAL DES-CBC-MD5, RC4       CRITICAL    Windows Server 2016

  Summary:
    Total DCs: 3
    DES Configured: 1
    RC4 Configured: 1
    AES Configured: 1


  EVENT LOG ANALYSIS SUMMARY
  ────────────────────────────────────────────────────────────────
  
  Domain Controller  Status   Events Analyzed  RC4 Tickets  DES Tickets
  -----------------  ------   ---------------  -----------  -----------
  DC01.contoso.com   Success  12,543           0            0
  DC02.contoso.com   Success  11,892           5            0
  DC03.contoso.com   Failed   0                0            0

  Summary:
    Total Events Analyzed: 24,435
    RC4 Tickets Detected: 5
    Failed DC Queries: 1
```

**Color Coding:**
- 🟢 **Green** - OK/Success status
- 🟡 **Yellow** - WARNING status
- 🔴 **Red** - CRITICAL/Failed status

**Forest-Wide** (when using Assess-ADForest.ps1):
Tables are grouped by domain, showing all DCs, event logs, and trusts across the entire forest.

---

## 📊 Understanding the Results

### Overall Status
- **🟢 OK** - No DES/RC4 usage detected, environment is ready for July 2026
- **🟡 WARNING** - RC4 detected, should be removed before July 2026 deadline
- **🔴 CRITICAL** - DES detected or active RC4 usage in event logs

### Domain Controllers
- **AES Configured** - DCs with AES encryption (good)
- **RC4 Configured** - DCs allowing RC4 (warning - inline fix command provided)
- **DES Configured** - DCs allowing DES (critical - remove immediately)
- **Not Configured (GPO Inherited)** - DCs getting settings from GPO (normal)

### KRBTGT & Service Accounts (v2.2.0+)
- **KRBTGT Password Age** - Should be rotated regularly (guidance provided)
- **USE_DES_KEY_ONLY** - Accounts with this UAC flag need remediation
- **RC4/DES-only SPN Accounts** - Service accounts missing AES (fix commands shown)
- **gMSA/sMSA** - Managed service accounts reviewed for weak encryption
- **Stale Passwords** - Service accounts >365 days old with RC4 enabled

### KDC Registry (v2.3.0+)
- **DefaultDomainSupportedEncTypes** - OS-level encryption defaults
- **RC4DefaultDisablementPhase** - Should be set to 1 after January 2026 updates

### Missing AES Keys (v2.3.0+)
- Accounts with passwords set before Domain Functional Level was raised to 2008
- These accounts have no AES keys generated — password reset required

### Trusts (Post-November 2022 Logic)
- **AES Default (not set)** - Trusts with no msDS-SupportedEncryptionTypes (✓ secure)
- **AES Explicit** - Trusts with AES explicitly configured (✓ secure)
- **RC4 Risk** - Trusts with RC4 enabled (⚠ remove before July 2026)
- **DES Risk** - Trusts with DES enabled (🔴 critical)

### Event Logs (Most Important!)
- **Audit Policy** - Script verifies Kerberos auditing is enabled before querying
- **AES Tickets** - Kerberos tickets using AES (✓ expected)
- **RC4 Tickets** - Active RC4 usage (⚠ investigate clients)
- **DES Tickets** - Active DES usage (🔴 critical - legacy systems)

### Inline Remediation Commands (v2.3.0+)
Every finding includes copy-paste PowerShell commands to fix the issue, including `klist purge` for cache clearing.

---

## 🚀 Migration Path (Preparing for July 2026)

### Phase 1: Initial AD Scan
```powershell
.\RC4_DES_Assessment.ps1 -QuickScan
```
Get baseline configuration (DCs, GPOs, Trusts, KRBTGT, Service Accounts, KDC Registry).

### Phase 2: Usage Analysis
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168 -ExportResults
```
Analyze 7 days of event logs to detect actual DES/RC4 usage. Export for comparison.

### Phase 3: Remediate
Follow the inline fix commands shown with every finding:
- `Set-ADComputer` / `Set-ADUser` for encryption types
- `Set-ItemProperty` for KDC registry keys (`RC4DefaultDisablementPhase`)
- `Set-ADAccountPassword` + `klist purge` for accounts needing AES key generation

### Phase 4: Validate & Track Progress
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168 -ExportResults
.\Compare-Assessments.ps1 -BaselineFile week1.json -CurrentFile week2.json -ShowDetails
```
Compare assessments to verify remediation progress.

### Phase 5: Monitoring Setup
```powershell
.\RC4_DES_Assessment.ps1 -IncludeGuidance
```
Get Splunk/SIEM queries, KRBTGT rotation guidance, and continuous monitoring setup.

---

## 🆘 Troubleshooting

### Event Log Access Issues (NEW in v2.0.1)

**Problem:** Script shows "RPC server unavailable" or "Access denied" when querying DCs

**Solution:** The script now provides automatic troubleshooting guidance. When failures occur, you'll see:
- Which DCs failed and the specific error
- Four detailed options to fix the issue
- PowerShell commands to run

**Test the Error Handling:**
```powershell
# Simulate RPC failures to see the troubleshooting output
.\Test-EventLogFailureHandling.ps1 -TestScenario MixedFailures
```

Available test scenarios:
- `RPCFailure` - Simulates RPC server unavailable
- `WinRMFailure` - Simulates PowerShell Remoting issues
- `AccessDenied` - Simulates permission errors
- `NetworkFailure` - Simulates network connectivity issues
- `MixedFailures` - Realistic scenario with multiple failure types
- `AllSuccess` - Control test (no failures)

### "Cannot find Active Directory module"
**Solution**: Install RSAT tools or run on domain controller
```powershell
# Windows 10/11
Get-WindowsCapability -Name RSAT.ActiveDirectory* -Online | Add-WindowsCapability -Online

# Windows Server
Install-WindowsFeature RSAT-AD-PowerShell
```

### "Access Denied" when querying DCs
**Solution**: Run PowerShell as Domain Admin or user with appropriate permissions

### "Cannot connect to domain"
**Solution**: Verify network connectivity and DNS resolution
```powershell
Test-Connection -ComputerName your-dc-name
Resolve-DnsName your-domain.com
```

### Child Domain Issues
**Problem:** Errors when running against child domains

**Solution:** Use both `-Domain` and `-Server` parameters:
```powershell
.\RC4_DES_Assessment.ps1 -Domain child.contoso.com -Server DC01.child.contoso.com -AnalyzeEventLogs
```

### Emojis not displaying correctly
**Solution**: Already fixed in v2.0.1! Script uses UTF-8 encoding and compatible Unicode characters for PowerShell 5.1

### Script runs very slowly
**Solution**: Use `-QuickScan` to skip event log analysis
```powershell
.\RC4_DES_Assessment.ps1 -QuickScan
```

---

## 📚 Additional Resources

- **README.md** - Comprehensive documentation with full sample outputs and July 2026 timeline
- **Compare-Assessments.ps1** - Track remediation progress between two assessment exports
- **Test-EventLogFailureHandling.ps1** - Test script for error handling validation
- **archive/README_v1_LEGACY.md** - Legacy v1.0 documentation (archived)
- **[KB5021131](https://support.microsoft.com/kb/5021131)** - Managing Kerberos protocol changes
- **[Detect and Remediate RC4](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-rc4)** - Microsoft guidance
- **[Microsoft Kerberos-Crypto](https://github.com/microsoft/Kerberos-Crypto)** - Microsoft's Kerberos crypto scripts

---

## 🎯 What's New

### v2.3.0 (March 2026) — Current
- **KDC registry assessment** - `DefaultDomainSupportedEncTypes` and `RC4DefaultDisablementPhase` checked on all DCs
- **Kerberos audit policy pre-check** - Verifies auditing is enabled before event log analysis
- **Missing AES keys detection** - Accounts with passwords predating DFL 2008 raise (no AES keys)
- **Inline remediation commands** - Every finding includes copy-paste PowerShell fix commands
- **July 2026 RC4 removal timeline** - January 2026 and July 2026 milestone guidance
- **Explicit RC4 exception workflow** - `0x1C` pattern for accounts that cannot use AES
- **`klist purge`** - Included in all remediation steps for cache clearing
- **Compare-Assessments.ps1** - Now compares account changes, registry keys, missing AES keys

### v2.2.0 (February 2026)
- **KRBTGT assessment** - Password age and encryption type checks with rotation guidance
- **USE_DES_KEY_ONLY detection** - Accounts with this UserAccountControl flag
- **Service account scan** - SPN accounts, gMSA/sMSA with RC4/DES-only encryption
- **Stale password detection** - Service accounts >365 days old with RC4 enabled

### v2.1.0 (December 2025)
- WinRM-first event log queries with RPC fallback
- Full forest DC enumeration per domain
- Child domain support fixes
- Comprehensive summary tables
- Assess-ADForest.ps1 for forest-wide scanning

---

## 🔄 Common Workflows

### Workflow 1: Quick Domain Health Check (1 minute)
```powershell
# Single command for domain readiness
.\RC4_DES_Assessment.ps1 -QuickScan

# Expected output includes:
# ✅ All Domain Controllers have AES encryption configured
# ✅ KRBTGT password age: 21 days
# ✅ No service accounts with RC4/DES-only encryption
# ✅ Trusts use AES by default
# ⚠️  RC4DefaultDisablementPhase not set (inline fix shown)
```

---

### Workflow 2: Deep Event Log Analysis (5 minutes)
```powershell
# Analyze 7 days of actual usage across ALL DCs
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168 -ExportResults

# Script auto-discovers all DCs and shows per-DC results:
# • Querying DC01.contoso.com...
#   ✓ Retrieved 15,234 events from DC01.contoso.com
# • Querying DC02.contoso.com...
#   ✓ Retrieved 12,456 events from DC02.contoso.com
# • Querying DC03.contoso.com...
#   ✗ RPC/Network error on DC03.contoso.com
```

---

### Workflow 3: Multi-Domain Forest Assessment (10-15 minutes)
```powershell
# Assess all domains in forest with parallel processing
.\Assess-ADForest.ps1 -AnalyzeEventLogs -ExportResults -Parallel -MaxParallelDomains 3

# Forest output shows per-domain DC discovery and assessment results
```

---

### Workflow 4: Child Domain with Connectivity Issues (3 minutes)
```powershell
# Problem: Auto-discovery fails for child domain
.\RC4_DES_Assessment.ps1 -Domain labs.contoso.com -AnalyzeEventLogs

# Solution: Specify a known DC
.\RC4_DES_Assessment.ps1 -Server DC01.labs.contoso.com -AnalyzeEventLogs
```

---

### Workflow 5: Track Remediation Progress (5 minutes per run)
```powershell
# Week 1: Baseline
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168 -ExportResults

# Week 2: After fixes
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168 -ExportResults

# Compare
.\Compare-Assessments.ps1 -BaselineFile old.json -CurrentFile new.json -ShowDetails
```

---

## 💡 Pro Tips

1. **Start with QuickScan** - Get quick results, then add event log analysis
2. **Use Forest Assessment for multi-domain environments** - `Assess-ADForest.ps1` automates domain enumeration
3. **Enable parallel processing** - Use `-Parallel` with PowerShell 7+ for faster forest assessments
4. **Monitor for 7+ days** - Use `-EventLogHours 168` to capture weekly activity patterns
5. **Track progress with Compare-Assessments** - Export baseline, remediate, export again, then compare
6. **Deploy January 2026 updates** - Set `RC4DefaultDisablementPhase = 1` on all DCs
7. **Export results** - Keep historical data for compliance/auditing (saved to `.\Exports` folder)
8. **Include guidance** - `-IncludeGuidance` shows audit setup, SIEM queries, KRBTGT rotation, July 2026 timeline
9. **Use -Server for child domains** - Specify a known DC when auto-discovery fails
10. **Copy-paste fix commands** - Every finding now includes inline remediation commands

---

## ✅ Validation Checklist

When you have AD access:
- [ ] Quick scan completes successfully
- [ ] DCs detected and assessed
- [ ] GPO encryption settings retrieved
- [ ] KRBTGT password age and encryption assessed
- [ ] Service accounts scanned for RC4/DES-only encryption
- [ ] USE_DES_KEY_ONLY accounts detected
- [ ] KDC registry keys checked on all DCs
- [ ] Missing AES keys detection runs
- [ ] Trusts enumerated correctly
- [ ] Inline fix commands shown for any findings
- [ ] Audit policy pre-check works (if using -AnalyzeEventLogs)
- [ ] Event log analysis works (if using -AnalyzeEventLogs)
- [ ] Export creates JSON/CSV files in `.\Exports` folder (if using -ExportResults)
- [ ] Compare-Assessments tracks changes between two exports
