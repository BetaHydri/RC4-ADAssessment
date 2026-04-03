# RC4-ADAssessment Module — Quick Start Guide

> **v3.0:** This toolkit is now a PowerShell module. Install with `Install-Module RC4-ADAssessment` or import from a local build.

## 🔐 Using with Active Directory

### Prerequisites
- PowerShell 5.1 or later (7+ for parallel forest assessment)
- Active Directory PowerShell module (`RSAT-AD-PowerShell`)
- Group Policy PowerShell module (`GPMC`)
- Domain Admin or equivalent permissions
- Network access to domain controllers (WinRM 5985 or RPC 135)

### Install & Import
```powershell
# Install from PSGallery (once published)
Install-Module -Name RC4-ADAssessment

# Or import from local build
Import-Module ./output/builtModule/RC4-ADAssessment
```

### Quick Scan (Fastest - No Event Logs)
```powershell
Invoke-RC4Assessment
```
**Runtime**: ~30 seconds
**Checks**: DCs, GPOs, Trusts, KRBTGT, Service Accounts (incl. dMSA), DES flags, Missing AES keys, RC4 exceptions, AzureADKerberos detection

### Deep Scan (Extended Account Coverage)
```powershell
Invoke-RC4Assessment -DeepScan
```
**Runtime**: ~1-2 minutes
**Checks**: All of the above + all enabled user accounts (not just SPN-bearing) + all computer accounts (excluding DCs) for RC4/DES configurations

> **Note**: `-DeepScan` does NOT analyze event logs or query remote DC registries. Combine with `-AnalyzeEventLogs` for maximum coverage.

### Full Assessment (Recommended)
```powershell
Invoke-RC4Assessment -AnalyzeEventLogs -EventLogHours 24
```
**Runtime**: 2-5 minutes
**Checks**: Quick scan + KDC registry, KDCSVC events (CVE-2026-20833), audit policy, Security event logs (4768/4769)

### Maximum Coverage
```powershell
Invoke-RC4Assessment -DeepScan -AnalyzeEventLogs -EventLogHours 168 -ExportResults
```
**Runtime**: 3-10 minutes
**Checks**: Everything — deep account scan + 7 days of event logs + full remote DC analysis

### With Export
```powershell
Invoke-RC4Assessment -AnalyzeEventLogs -ExportResults
```
**Output**: JSON and CSV files with timestamp in `.\Exports\`

### With Full Reference Manual
```powershell
Invoke-RC4Assessment -IncludeGuidance
```
**Shows**: Audit setup, SIEM/Splunk queries, KRBTGT rotation guidance, July 2026 timeline

### Specific Domain
```powershell
Invoke-RC4Assessment -Domain contoso.com -AnalyzeEventLogs
```

### Specific Domain — Full Assessment with Export & Guidance
```powershell
Invoke-RC4Assessment -Domain contoso.com -AnalyzeEventLogs -ExportResults -IncludeGuidance
```
**Runtime**: 2-5 minutes
**Output**: JSON, CSV, and guidance text files in `.\Exports\` + reference manual displayed

### Forest-Wide Assessment
```powershell
# Quick scan all domains in forest
Invoke-RC4ForestAssessment

# Full assessment with event logs
Invoke-RC4ForestAssessment -AnalyzeEventLogs -ExportResults

# Parallel processing (PowerShell 7+)
Invoke-RC4ForestAssessment -Parallel -MaxParallelDomains 5 -AnalyzeEventLogs
```
**Runtime**: Varies (parallel mode processes multiple domains concurrently)
**Output**: Per-domain JSON exports + forest-wide summary

### Compare Two Runs (Track Progress)
```powershell
Invoke-RC4AssessmentComparison -BaselineFile before.json -CurrentFile after.json -ShowDetails
```
**Compares**: DC encryption, trusts, accounts (KRBTGT, service accounts, DES flags, missing AES keys), KDC registry, KDCSVC events (CVE-2026-20833), event log tickets

---

## 📊 Sample Output

### Successful Quick Scan
```
================================================================================
DES/RC4 Kerberos Encryption Assessment v2.9.0
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
   Deploy January 2026+ security updates, then set to 1 to enable KDCSVC audit events

KDCSVC System Event Assessment (CVE-2026-20833)
────────────────────────────────────────────────────────────────
✅ No KDCSVC events found - no RC4 risks detected (CVE-2026-20833)
  Note: KDCSVC events require RC4DefaultDisablementPhase >= 1 to be logged

Trust Encryption Assessment (Post-November 2022 Logic)
────────────────────────────────────────────────────────────────
ℹ️  Found 1 trust(s)
✅ Trust 'partner.com': Uses AES by default (msDS-SupportedEncryptionTypes not set)

Overall Security Assessment
────────────────────────────────────────────────────────────────
⚠️  Security warnings detected - remediation recommended

  Recommendations & Remediation:
    • WARNING: [contoso.com] RC4DefaultDisablementPhase not set
      # Step 1: Deploy January 2026+ security updates on all DCs
      # Step 2: Enable KDCSVC audit events (System log events 201-209):
      PS> Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
            -Name 'RC4DefaultDisablementPhase' -Value 1 -Type DWord
      # Step 3: Monitor KDCSVC events and remediate any RC4 dependencies
      # Step 4: When audit events are clear, enable Enforcement mode (value 2)

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
      # If AES fails, add explicit RC4 exception (CVE-2026-20833 safe):
      #   -Replace @{'msDS-SupportedEncryptionTypes'=0x1C}
      #   0x1C = RC4 + AES128 + AES256
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
  Import module on DC and run:
  PS> Import-Module RC4-ADAssessment
  PS> Invoke-RC4Assessment -AnalyzeEventLogs -EventLogHours 24

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

**Forest-Wide** (when using `Invoke-RC4ForestAssessment`):
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
- **Linux Keytab Impact** - KRBTGT or service account password rotation invalidates Kerberos keytab files; Linux services (Apache, SSSD, Samba, PostgreSQL, etc.) must regenerate keytabs after rotation
- **USE_DES_KEY_ONLY** - Accounts with this UAC flag need remediation
- **RC4/DES-only SPN Accounts** - Service accounts missing AES (fix commands shown)
- **gMSA/sMSA** - Managed service accounts reviewed for weak encryption
- **Stale Passwords** - Service accounts >365 days old with RC4 enabled

### KDC Registry (v2.3.0+)
- **DefaultDomainSupportedEncTypes** - OS-level encryption defaults
- **RC4DefaultDisablementPhase** - Set to 1 (Audit) then 2 (Enforce) per CVE-2026-20833

### KDCSVC System Events (v2.4.0+)
- **Events 201-209** - KDCSVC events in System log indicating RC4 risks (CVE-2026-20833)
- Requires `RC4DefaultDisablementPhase >= 1` to be logged
- Events 201-203: Audit warnings (RC4 requested for default accounts)
- Events 206-208: Enforcement blocks (RC4 blocked in Enforcement mode)

### Missing AES Keys (v2.3.0+)
- Accounts with passwords set before Domain Functional Level was raised to 2008
- These accounts have no AES keys generated — password reset required

### AzureADKerberos (v2.5.0+)
- **Entra Kerberos proxy** object in DC OU is auto-detected and excluded from DC counts
- Separate informational display in summary tables and exports
- Its `krbtgt` keys are **not** auto-rotated — rotate regularly using `Set-AzureADKerberosServer -Domain <domain> -CloudCredential $cloudCred -DomainCredential $domainCred -RotateServerKey` (requires `AzureADHybridAuthenticationManagement` module)
- Key rotation invalidates Kerberos keytab files for Linux services — regenerate keytabs after rotation

### RC4 Exception Accounts (v2.6.0+)
- Accounts with explicit RC4 + AES (`0x1C`) flagged as WARNING
- AES-first hardening: default fix commands now use `0x18` (AES-only)
- `0x1C` recommended only as last resort when AES breaks an application

### DES-Enabled Accounts (v2.5.1+)
- Accounts with DES bits set alongside AES are flagged as WARNING (DES removed in Server 2025)
- Covers SPN user accounts, gMSA, sMSA, and dMSA

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

### Phase 1: Discovery (DCs, trusts, service accounts, logs)
```powershell
Invoke-RC4Assessment -AnalyzeEventLogs -ExportResults
```
Focus on the highest-risk items first: DCs, trusts, KRBTGT, service accounts, KDC registry, KDCSVC events, and event logs. No `-DeepScan` yet — avoid drowning in bulk account findings before critical items are fixed.

### Phase 2: Remediate (high-risk items)
Follow the inline fix commands shown with every finding:
- `Set-ADComputer` / `Set-ADUser` for DC and service account encryption types
- `Set-ItemProperty` for KDC registry keys (`RC4DefaultDisablementPhase`)
- `Set-ADAccountPassword` + `klist purge` for service accounts needing AES key generation

### Phase 3: Validate
```powershell
Invoke-RC4Assessment -AnalyzeEventLogs -ExportResults
Invoke-RC4AssessmentComparison -BaselineFile before.json -CurrentFile after.json -ShowDetails
```
Compare assessments to confirm all critical items are resolved before moving on.

### Phase 4: Deep Sweep (all users + computers)
```powershell
Invoke-RC4Assessment -DeepScan -AnalyzeEventLogs -ExportResults
```
Now scan all enabled user accounts and computer accounts for remaining RC4/DES configurations.

### Phase 5: Final Remediate (bulk cleanup)
- Password resets for remaining accounts with missing AES keys
- Address any non-default computer account encryption configs

### Phase 6: Final Validate
```powershell
Invoke-RC4AssessmentComparison -BaselineFile deep-before.json -CurrentFile deep-after.json -ShowDetails
```
Confirm everything is clean. Repeat Phase 5–6 as needed.

### Ongoing: Monitoring Setup
```powershell
Invoke-RC4Assessment -IncludeGuidance
```
Get Splunk/SIEM queries, KRBTGT rotation guidance, and continuous monitoring setup.

---

## 🆘 Troubleshooting

### Event Log Access Issues (NEW in v2.0.1)

**Problem:** Module shows "RPC server unavailable" or "Access denied" when querying DCs

**Solution:** The module provides automatic troubleshooting guidance. When failures occur, you'll see:
- Which DCs failed and the specific error
- Four detailed options to fix the issue
- PowerShell commands to run

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
Invoke-RC4Assessment -Domain child.contoso.com -Server DC01.child.contoso.com -AnalyzeEventLogs
```

### Emojis not displaying correctly
**Solution**: Already fixed in v2.0.1! Script uses UTF-8 encoding and compatible Unicode characters for PowerShell 5.1

### Script runs very slowly
**Solution**: Run without `-AnalyzeEventLogs` to skip remote DC queries
```powershell
Invoke-RC4Assessment
```

---

## 📚 Additional Resources

- **README.md** — Comprehensive documentation with full sample outputs and July 2026 timeline
- **CHANGELOG.md** — Full version history
- **archive/README_v1_LEGACY.md** — Legacy v1.0 documentation (archived)
- **[KB5021131](https://support.microsoft.com/kb/5021131)** — Managing Kerberos protocol changes
- **[Detect and Remediate RC4](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-rc4)** — Microsoft guidance
- **[Microsoft Kerberos-Crypto](https://github.com/microsoft/Kerberos-Crypto)** — Microsoft's Kerberos crypto scripts

---

## 🎯 What's New

> For the complete version history with full details, see [CHANGELOG.md](CHANGELOG.md).

### v2.9.0 (March 2026) — Current

- **AES/RC4 correlation** (major) — Detects accounts with AES configured but still issuing RC4 tickets (password reset needed)
- **Event log deserialization fix** — Event analysis now correctly reports AES/RC4/DES ticket counts via remote XML parsing
- **Guidance text file export** — `-ExportResults -IncludeGuidance` generates a plain-text guidance file in `Exports/`
- **Per-DC event count fix** — Summary table now shows correct per-DC counts instead of aggregate totals
- **KDCSVC event reference table** — Event IDs 201–209 with descriptions and recommended actions
- **gMSA/sMSA creation guide** — Step-by-step Managed Service Account creation guidance

### v2.8.0 (March 2026)

- **lastLogonTimestamp for all flagged accounts** — Last Logon column in summary table, CSV, and JSON for triage prioritization
- **Fine-Grained Password Policy (FGPP) workaround guidance** — Zero-disruption AES key generation for service accounts
- **Explicit AES enforcement guidance** — Section 9c for cases where password reset alone doesn't generate AES keys
- **Missing AES key accounts in summary table** — Now appear alongside other account types
- **AzureADKerberos key rotation reminder** — `Set-AzureADKerberosServer -RotateServerKey` with module install steps

### v2.7.2 (March 2026)

- **SYSVOL GPO detection fallback fix**: Fixed silent failure in SYSVOL-based GPO encryption detection when GroupPolicy module is broken
- Fixed Pester test mock parameter type mismatch for `Get-ADComputer` and `Get-ADObject` stubs

### v2.7.1 (March 2026)

- **Linux / Kerberos keytab impact guidance** added to KRBTGT rotation procedure and service account remediation
- `ktpass` / `ktutil` keytab regeneration commands, verification steps, and reference links
- Inline keytab warnings in KRBTGT and service account fix recommendations

### v2.7.0 (March 2026)
- **DC discovery refactored to `Get-ADDomainController -Filter *`** - Uses DC Locator (Configuration partition) instead of OU queries — no false positives from non-DC objects
- AzureADKerberos filtering no longer needed for KDC registry, KDCSVC events, audit policy, event log functions
- AzureADKerberos detection uses targeted `Get-ADComputer -Identity 'AzureADKerberos'` lookup

### v2.6.0 (March 2026)
- **AES-first hardening** - Default fix commands use `0x18` (AES-only); `0x1C` only as documented fallback
- **RC4 exception account detection** - Accounts with explicit RC4 + AES flagged as WARNING
- Updated guidance: AES-first approach with clear "last resort" language for RC4 exceptions

### v2.5.1 (March 2026)
- **DES-enabled account detection** - Accounts with DES bits alongside AES flagged as WARNING
- **dMSA support** - Delegated Managed Service Accounts (Server 2025) correctly identified
- **AzureADKerberos exclusion refinement** across KDC registry and KDCSVC queries

### v2.5.0 (March 2026)
- **AzureADKerberos detection** - Entra Kerberos proxy auto-detected and excluded from DC counts
- Separate informational display in summary tables and CSV/JSON exports

### v2.4.0 (March 2026)
- **CVE-2026-20833 support** - KDCSVC System event scanning (events 201-209)
- **`RC4DefaultDisablementPhase`** phased workflow (1 = Audit, 2 = Enforce)
- Explicit RC4 exception value `0x1C` (RC4 + AES128 + AES256)

### v2.3.0 (March 2026)
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
Invoke-RC4Assessment

# Expected output includes:
# ✅ All Domain Controllers have AES encryption configured
# ✅ KRBTGT password age: 21 days
# ✅ No service accounts with RC4/DES-only encryption
# ✅ Trusts use AES by default
# ℹ️  Remote DC analysis skipped. Use -AnalyzeEventLogs to enable.
```

---

### Workflow 2: Deep Account Scan (1-2 minutes)
```powershell
# Scan all user and computer accounts for RC4/DES issues
Invoke-RC4Assessment -DeepScan

# Note: This does NOT query event logs or remote DC registries.
# For full coverage, combine both switches:
Invoke-RC4Assessment -DeepScan -AnalyzeEventLogs -EventLogHours 168 -ExportResults
```

---

### Workflow 3: Deep Event Log Analysis (5 minutes)
```powershell
# Analyze 7 days of actual usage across ALL DCs
Invoke-RC4Assessment -AnalyzeEventLogs -EventLogHours 168 -ExportResults

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
Invoke-RC4ForestAssessment -AnalyzeEventLogs -ExportResults -Parallel -MaxParallelDomains 3

# Forest output shows per-domain DC discovery and assessment results
```

---

### Workflow 4: Child Domain with Connectivity Issues (3 minutes)
```powershell
# Problem: Auto-discovery fails for child domain
Invoke-RC4Assessment -Domain labs.contoso.com -AnalyzeEventLogs

# Solution: Specify a known DC
Invoke-RC4Assessment -Server DC01.labs.contoso.com -AnalyzeEventLogs
```

---

### Workflow 5: Track Remediation Progress (5 minutes per run)
```powershell
# Week 1: Baseline
Invoke-RC4Assessment -AnalyzeEventLogs -EventLogHours 168 -ExportResults

# Week 2: After fixes
Invoke-RC4Assessment -AnalyzeEventLogs -EventLogHours 168 -ExportResults

# Compare
Invoke-RC4AssessmentComparison -BaselineFile old.json -CurrentFile new.json -ShowDetails
```

---

## 💡 Pro Tips

1. **Start with a quick scan** - Run `Invoke-RC4Assessment` for quick results, then add `-DeepScan` for full account coverage, and `-AnalyzeEventLogs` for remote DC analysis
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
