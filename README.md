# DES/RC4 Kerberos Encryption Assessment v2.1

> **📌 Note:** Legacy v1.0 files are archived in the [`archive/`](archive/) folder for reference.

## Overview

A completely redesigned tool for assessing DES and RC4 encryption usage in Active Directory environments, addressing critical limitations discovered in v1.0 and incorporating post-November 2022 Microsoft Kerberos security updates.

## What's New in v2.1.0

### Enhanced Multi-Domain & Event Log Support

🎯 **WinRM-First Event Queries** - Invoke-Command now primary method (more reliable than RPC for child domains)  
🎯 **Full Forest DC Enumeration** - Discovers and queries ALL DCs in each domain when using Assess-ADForest.ps1  
🎯 **Improved Child Domain Support** - Fixed Get-ADDomain parameter handling for cross-domain queries  
🎯 **Deserialized Event Handling** - Properly processes events from remote DCs via PowerShell Remoting  
🎯 **Specific DC Error Reporting** - Shows exactly which DC failed (e.g., "DC01.child.contoso.com")  
🎯 **ADPropertyValueCollection Fix** - Resolves HostName conversion errors during DC discovery  
🎯 **Summary Tables** - Comprehensive summary tables showing all DC findings at end of assessment

### Version History

**v2.1.0** (December 2025)
- WinRM-first approach for event log queries (Invoke-Command before Get-WinEvent -ComputerName)
- Fixed deserialized event object processing from remote DCs
- Enhanced forest assessment with automatic DC discovery per domain
- Improved error messages showing specific DC names for failures
- Fixed Get-ADDomain -Identity parameter issue for child domains
- Resolved ADPropertyValueCollection to string conversion errors
- Full DC enumeration in each forest domain (not just first 3)
- Per-DC success/failure reporting with specific error details
- Added comprehensive summary tables for single-domain and forest-wide assessments

**v2.0.1** (November 2025)
- Enhanced remote event log access troubleshooting
- Comprehensive RPC/WinRM failure guidance
- Child domain identity parameter fixes
- Better error categorization (WinRM, RPC, permission, network)

**v2.0.0** (October 2025)
- Complete rewrite with post-November 2022 logic
- Fast execution (< 5 minutes vs 5+ hours in v1.0)
- Event-based actual usage detection
- Realistic computer object assessment

## Why Version 2.0?

### Customer Feedback on v1.0

Real-world deployment revealed several critical issues:

1. **Performance**: 5.5+ hours to complete in large forests (unacceptable for production use)
2. **Confusion**: Unclear guidance on `msDS-SupportedEncryptionTypes` requirements
3. **Outdated Logic**: Pre-November 2022 trust encryption assumptions
4. **False Positives**: Flagged theoretical risks instead of actual usage
5. **Missing Validation**: No guidance for manual checks and event monitoring

### Key Improvements in v2.0+

✅ **Fast Execution**: < 5 minutes vs 5+ hours  
✅ **Post-Nov 2022 Logic**: Accurate trust and computer encryption assessment  
✅ **Event-Based Analysis**: Detects actual DES/RC4 usage from Kerberos tickets  
✅ **Clear Guidance**: Actionable manual validation steps and SIEM queries  
✅ **Realistic Assessment**: No unnecessary computer object enumeration  
✅ **Full Forest Support**: Assess all domains and all DCs automatically  
✅ **Child Domain Ready**: Works across complex multi-domain forests

## Post-November 2022 Updates - Critical Understanding

### Computer Objects and RC4 Fallback

**OLD UNDERSTANDING (Incorrect):**
> Every computer object must have `msDS-SupportedEncryptionTypes` populated, otherwise RC4 fallback occurs.

**CURRENT REALITY (Post-Nov 2022):**
> RC4 fallback ONLY occurs when BOTH conditions are true:
> 1. `msDS-SupportedEncryptionTypes` on CLIENT is set to non-zero value
> 2. `msDS-SupportedEncryptionTypes` on DC does NOT include AES
>
> If DCs have AES configured via GPO, clients inherit AES even if their attribute is empty/0.

**Impact:** You do NOT need to populate `msDS-SupportedEncryptionTypes` on 100,000+ computers if your DCs are properly configured.

### Trust Encryption Defaults

**OLD UNDERSTANDING (Incorrect):**
> Trusts with `msDS-SupportedEncryptionTypes` not set will use RC4.

**CURRENT REALITY (Post-Nov 2022):**
> When `msDS-SupportedEncryptionTypes` is 0 or empty on trusts, they **default to AES**.
> No action needed for these trusts.

**Impact:** Trusts showing "0 secure trusts" in v1.0 are actually secure if the attribute is not set.

### Reference Documentation

- [KB5021131: Managing Kerberos protocol changes](https://support.microsoft.com/kb/5021131)
- [What happened to Kerberos authentication after November 2022 updates](https://techcommunity.microsoft.com/blog/askds/what-happened-to-kerberos-authentication-after-installing-the-november-2022oob-u/3696351)
- [Decrypting Kerberos Encryption Types Selection](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/decrypting-the-selection-of-supported-kerberos-encryption-types/1628797)

## Installation & Prerequisites

### Required PowerShell Modules

```powershell
# Install RSAT tools on Windows 10/11 client
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0

# Or on Windows Server
Install-WindowsFeature RSAT-AD-PowerShell, GPMC
```

### Prerequisites
- **PowerShell:** 5.1 or later (PowerShell 7+ recommended for parallel forest assessment)
- **Modules:** Active Directory (`RSAT-AD-PowerShell`), Group Policy (`GPMC`)
- **Permissions:** Domain Admin or equivalent read permissions (Event Log Readers for event analysis)
- **Network:** Access to domain controllers (WinRM port 5985 or RPC port 135)

### Quick Verification

```powershell
# Verify modules are installed
Get-Module -ListAvailable ActiveDirectory, GroupPolicy

# Test connectivity
Import-Module ActiveDirectory, GroupPolicy
Get-ADDomain
```

## Features

### Core Scripts

1. **RC4_DES_Assessment.ps1** - Main assessment tool (v2.1.0)
2. **Assess-ADForest.ps1** - Forest-wide assessment wrapper (v2.1.0)
3. **Compare-Assessments.ps1** - Compare assessment results over time
4. **Test-EventLogFailureHandling.ps1** - Test script for event log error handling validation

### Fast Assessment (Default - Quick Scan)
- Domain Controller encryption configuration
- GPO Kerberos policy analysis
- Trust encryption assessment (post-Nov 2022 logic)
- Overall security posture
- **Runtime:** < 2 minutes

### Full Assessment (With Event Log Analysis)
- Everything in Quick Scan, plus:
- Event log analysis for actual DES/RC4 ticket usage
- Detection of accounts actively using weak encryption
- Real-world vs theoretical risk assessment
- **Runtime:** 3-10 minutes depending on event volume

### Manual Validation Guidance
- Event log monitoring setup instructions
- Splunk/SIEM query examples
- GPO validation procedures
- Computer object assessment (when needed)
- Trust validation steps
- Windows Server 2025 preparation

## Sample Output

### Example 1: Quick Scan - Healthy Environment

```powershell
PS> .\RC4_DES_Assessment.ps1 -QuickScan
```

```
================================================================================
DES/RC4 Kerberos Encryption Assessment v2.1
================================================================================

This tool performs a fast, accurate assessment of DES and RC4 encryption usage
in Active Directory based on post-November 2022 Microsoft updates.

Key improvements over v1.0:

  ✓ Fast execution (<5 minutes vs 5+ hours)
  ✓ Post-Nov 2022 trust logic (AES default when not set)
  ✓ Realistic computer object assessment (no unnecessary enumeration)
  ✓ Event log analysis for actual usage vs theoretical risk
  ✓ Actionable guidance for manual validation


Domain Controller Encryption Configuration
────────────────────────────────────────────────────────────────
ℹ️  Analyzing domain: contoso.com
ℹ️  Found 3 Domain Controller(s)

  Checking GPO Kerberos encryption policy...
✅ GPO 'Default Domain Controllers Policy' configures Kerberos encryption
   Encryption types: AES128-HMAC, AES256-HMAC

ℹ️  Domain Controller Summary:
  • Total DCs: 3
  • AES Configured: 0
  • RC4 Configured: 0
  • DES Configured: 0
  • Not Configured (GPO Inherited): 3

  Individual DC Status:
    • DC01: Not Configured (Inherits from GPO)
    • DC02: Not Configured (Inherits from GPO)
    • DC03: Not Configured (Inherits from GPO)

✅ Domain Controllers are configured for AES encryption via GPO
ℹ️  3 DC(s) inherit AES settings from GPO (this is normal)


Trust Encryption Assessment (Post-November 2022 Logic)
────────────────────────────────────────────────────────────────
ℹ️  Found 1 trust(s)
✅ Trust 'partner.contoso.com': Uses AES by default (msDS-SupportedEncryptionTypes not set)

ℹ️  Trust Assessment Summary:
  • Total Trusts: 1
  • AES Default (not set): 1
  • AES Explicit: 0
  • RC4 Risk: 0
  • DES Risk: 0

  📘 Post-November 2022 Update:
  When msDS-SupportedEncryptionTypes is not set (0 or empty) on trusts,
  they default to AES encryption. No action needed for these trusts.


Overall Security Assessment
────────────────────────────────────────────────────────────────
✅ No DES/RC4 usage detected - environment is secure

  💡 Tip: Use -IncludeGuidance to see detailed manual validation steps and monitoring setup.


Assessment Complete
================================================================================

📊 Summary:
  • Domain: contoso.com
  • Assessment Date: 2025-12-03 14:30:15
  • Overall Status: OK

  💡 For complete assessment, run with -AnalyzeEventLogs to detect actual DES/RC4 usage
```

---

### Example 2: Full Assessment with Event Logs - RC4 Detected

```powershell
PS> .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 48
```

```
================================================================================
DES/RC4 Kerberos Encryption Assessment v2.0
================================================================================

[... DC and Trust assessment similar to Example 1 ...]


Event Log Analysis - Actual DES/RC4 Usage
────────────────────────────────────────────────────────────────
ℹ️  Analyzing last 48 hours of Kerberos ticket events
  Time range: 2025-12-01 14:30 to 2025-12-03 14:30
ℹ️  Querying event logs from 3 Domain Controller(s)...
  Note: Using WinRM (PowerShell Remoting) for event log queries
  If this fails, ensure WinRM is enabled on DCs: Enable-PSRemoting -Force
  • Querying DC01...
  • Querying DC02...
  • Querying DC03...

ℹ️  Event Log Analysis Results:
  • Events Analyzed: 31,287
  • AES Tickets: 31,279
  • RC4 Tickets: 8
  • DES Tickets: 0

❌ RC4 tickets detected in active use!
  Unique accounts using RC4: 3
  RC4 accounts:
    - LEGACY-APP$
    - SQL2008-SRV$
    - FILESERVER01$
✅ No DES tickets detected in last 48 hours


Overall Security Assessment
────────────────────────────────────────────────────────────────
❌ Critical security issues detected requiring immediate attention

  Recommendations:
    • CRITICAL: RC4 tickets detected in event logs - active usage detected

Assessment Complete
================================================================================

📊 Summary:
  • Domain: contoso.com
  • Assessment Date: 2025-12-03 14:32:45
  • Overall Status: CRITICAL
```

---

### Example 3: Assessment with Event Log Access Issues

```powershell
PS> .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 24
```

```
Event Log Analysis - Actual DES/RC4 Usage
────────────────────────────────────────────────────────────────
ℹ️  Analyzing last 24 hours of Kerberos ticket events
  Time range: 2025-12-02 14:30 to 2025-12-03 14:30
ℹ️  Querying event logs from 3 Domain Controller(s)...
  Note: Using WinRM (PowerShell Remoting) for event log queries
  If this fails, ensure WinRM is enabled on DCs: Enable-PSRemoting -Force
  • Querying DC01...
    ⚠️  RPC/Network error on DC01
       Both WinRM (5985) and RPC (135) failed. Check firewall rules or run locally on DC

    Troubleshooting:
    1. Enable WinRM on DC: Enable-PSRemoting -Force
    2. Or allow RPC in firewall: Port 135 + 49152-65535
    3. Or run this script directly on the DC
    4. Check permissions: Add your account to 'Event Log Readers' group

  • Querying DC02...
  • Querying DC03...
    ⚠️  Access denied on DC03
       Ensure you have Event Log Readers permissions or are Domain Admin

    Troubleshooting:
    1. Enable WinRM on DC: Enable-PSRemoting -Force
    2. Or allow RPC in firewall: Port 135 + 49152-65535
    3. Or run this script directly on the DC
    4. Check permissions: Add your account to 'Event Log Readers' group


ℹ️  Event Log Analysis Results:
  • Events Analyzed: 10,431
  • AES Tickets: 10,429
  • RC4 Tickets: 2
  • DES Tickets: 0

❌ RC4 tickets detected in active use!
  Unique accounts using RC4: 1
  RC4 accounts:
    - LEGACY-APP$

  ⚠️  Event Log Query Failures:
  2 Domain Controller(s) could not be queried for event logs

  • DC01: The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)
  • DC03: Access is denied. Attempted to perform an unauthorized operation.

  🔧 How to fix remote event log access issues:

  Option 1: Enable WinRM (Recommended)
  ────────────────────────────────────────
  Run on each failed DC:
  PS> Enable-PSRemoting -Force
  PS> Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*' -Force
  PS> Restart-Service WinRM

  Or via Group Policy (for all DCs):
  Computer Configuration > Policies > Administrative Templates
  > Windows Components > Windows Remote Management (WinRM) > WinRM Service
  - Enable 'Allow remote server management through WinRM'
  - IPv4 filter: * (or specific IPs)

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
  Or use Domain Admin account (has all required permissions)


Overall Security Assessment
────────────────────────────────────────────────────────────────
❌ Critical security issues detected requiring immediate attention

  Recommendations:
    • CRITICAL: RC4 tickets detected in event logs - active usage detected

  ⚠️  Note: Event log data is incomplete due to 2 DC(s) being inaccessible
     Review the detailed troubleshooting guidance in the Event Log Analysis section above
```

---

### Example 4: Export Results for Comparison

```powershell
PS> .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults
```

```
[... assessment output ...]

Exporting Results
────────────────────────────────────────────────────────────────
✅ JSON export: .\DES_RC4_Assessment_contoso_com_20251203_143015.json
✅ CSV export: .\DES_RC4_Assessment_contoso_com_20251203_143015.csv
```

**JSON Export Sample:**
```json
{
  "AssessmentDate": "2025-12-03T14:30:15",
  "Version": "2.1.0",
  "Domain": "contoso.com",
  "OverallStatus": "WARNING",
  "DomainControllers": {
    "TotalDCs": 3,
    "AESConfigured": 3,
    "RC4Configured": 0,
    "DESConfigured": 0,
    "NotConfigured": 0,
    "GPOConfigured": true,
    "GPOEncryptionTypes": 24,
    "Details": [
      {
        "Name": "DC01",
        "EncryptionValue": 24,
        "EncryptionTypes": "AES128-HMAC, AES256-HMAC",
        "OS": "Windows Server 2022 Datacenter",
        "Status": "AES Configured"
      }
    ]
  },
  "Trusts": {
    "TotalTrusts": 1,
    "ExplicitAES": 0,
    "DefaultAES": 1,
    "RC4Risk": 0,
    "DESRisk": 0
  },
  "EventLogs": {
    "EventsAnalyzed": 15432,
    "DESTickets": 0,
    "RC4Tickets": 2,
    "AESTickets": 15430,
    "RC4Accounts": ["LEGACY-APP$", "SQL2008-SRV$"],
    "FailedDCs": []
  },
  "Recommendations": [
    "CRITICAL: RC4 tickets detected in event logs - active usage detected"
  ]
}
```

---

### Example 5: Summary Tables (New in v2.1.0)

At the end of each assessment, comprehensive summary tables are displayed showing all findings:

```
Assessment Summary Tables
────────────────────────────────────────────────────────────────

  DOMAIN CONTROLLER SUMMARY
  ────────────────────────────────────────────────────────────────

  Domain Controller  Status   Encryption Types       Attribute Value  GPO Status  Operating System
  -----------------  ------   ----------------       ---------------  ----------  ----------------
  DC01.contoso.com   OK       AES128-HMAC, AES256    0x18             OK          Windows Server 2022
  DC02.contoso.com   WARNING  RC4-HMAC, AES128       0x14             WARNING     Windows Server 2019
  DC03.contoso.com   CRITICAL DES-CBC-MD5, RC4-HMAC  0x07             CRITICAL    Windows Server 2016

  Summary:
    Total DCs: 3
    DES Configured: 1
    RC4 Configured: 1
    AES Configured: 1


  EVENT LOG ANALYSIS SUMMARY
  ────────────────────────────────────────────────────────────────

  Domain Controller  Status   Events Analyzed  RC4 Tickets  DES Tickets  Error Message
  -----------------  ------   ---------------  -----------  -----------  -------------
  DC01.contoso.com   Success  12,543           0            0            -
  DC02.contoso.com   Success  11,892           5            0            -
  DC03.contoso.com   Failed   0                0            0            RPC server unavailable

  Summary:
    Total Events Analyzed: 24,435
    RC4 Tickets Detected: 5
    Failed DC Queries: 1


  TRUST ENCRYPTION SUMMARY
  ────────────────────────────────────────────────────────────────

  Trust Name       Direction  Encryption Types       Risk Level
  ----------       ---------  ----------------       ----------
  child.contoso    Bidirect   AES128-HMAC, AES256    LOW
  partner.com      Outbound   RC4-HMAC              HIGH

  Summary:
    Total Trusts: 2
    RC4 Risk: 1 trust(s)
    AES Secure: 1 trust(s)
```

**Forest-Wide Summary Tables** (when using Assess-ADForest.ps1):

```
================================================================================
FOREST-WIDE SUMMARY TABLES
================================================================================

  ALL DOMAIN CONTROLLERS ACROSS FOREST
  ────────────────────────────────────────────────────────────────

  Domain: contoso.com

    Domain Controller  Status   Encryption Types       Operating System
    -----------------  ------   ----------------       ----------------
    DC01.contoso.com   OK       AES128, AES256         Windows Server 2022
    DC02.contoso.com   WARNING  RC4-HMAC, AES128       Windows Server 2019

  Domain: child.contoso.com

    Domain Controller    Status   Encryption Types       Operating System
    -------------------  ------   ----------------       ----------------
    DC01.child.cont...   OK       AES128, AES256         Windows Server 2022
    DC02.child.cont...   CRITICAL DES-CBC-MD5, RC4       Windows Server 2016

  Forest-Wide DC Statistics:
    Total DCs: 4
    CRITICAL (DES): 1
    WARNING (RC4): 1
    OK (AES): 2


  EVENT LOG ANALYSIS - ALL DOMAINS
  ────────────────────────────────────────────────────────────────

  Domain: contoso.com

    Domain Controller  Status   Events  RC4  DES
    -----------------  ------   ------  ---  ---
    DC01.contoso.com   Success  12,543  0    0
    DC02.contoso.com   Success  11,892  5    0

  Domain: child.contoso.com

    Domain Controller    Status   Events  RC4  DES
    -------------------  ------   ------  ---  ---
    DC01.child.cont...   Success  8,234   0    0
    DC02.child.cont...   Failed   0       0    0

  Forest-Wide Event Statistics:
    Total Events Analyzed: 32,669
    RC4 Tickets: 5
    Failed Queries: 1
```

---

### Example 6: Comparing Results

**Comparing Results:**
```powershell
PS> .\Compare-Assessments.ps1 `
    -BaselineFile .\DES_RC4_Assessment_contoso_com_20251201_100000.json `
    -CurrentFile .\DES_RC4_Assessment_contoso_com_20251203_143015.json `
    -ShowDetails
```

```
================================================================================
Assessment Comparison Report
================================================================================

Baseline: DES_RC4_Assessment_contoso_com_20251201_100000.json (2025-12-01 10:00:00)
Current:  DES_RC4_Assessment_contoso_com_20251203_143015.json (2025-12-03 14:30:15)

Domain Controllers
────────────────────────────────────────────────────────────────
  Total DCs:          3 → 3 (unchanged)
  AES Configured:     2 → 3 (↑ +1 improved)
  RC4 Configured:     1 → 0 (↓ -1 improved)
  DES Configured:     0 → 0 (unchanged)

Trusts
────────────────────────────────────────────────────────────────
  Total Trusts:       1 → 1 (unchanged)
  RC4 Risk:           0 → 0 (unchanged)

Event Logs (if analyzed)
────────────────────────────────────────────────────────────────
  RC4 Tickets:        5 → 2 (↓ -3 improved)
  DES Tickets:        0 → 0 (unchanged)
  RC4 Accounts:       4 → 2 (↓ -2 improved)

Overall Assessment
────────────────────────────────────────────────────────────────
  Status:             WARNING → WARNING (unchanged)
  
✅ Improvements:
  • RC4 removed from 1 Domain Controller
  • 2 fewer accounts using RC4 tickets

⚠️  Remaining Issues:
  • 2 accounts still using RC4: LEGACY-APP$, SQL2008-SRV$
```

---

## Workflow Guidance

### Recommended Assessment Workflow

```
┌─────────────────────────────────────────────────────────────┐
│ Phase 1: Initial Discovery (5 minutes)                      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
        Run Quick Scan to assess baseline
        .\RC4_DES_Assessment.ps1 -QuickScan
                            │
                            ├─── ✅ All OK? ────► Continue monitoring
                            │
                            └─── ⚠ Issues Found
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 2: Actual Usage Analysis (10 minutes)                 │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
    Analyze 7 days of event logs for real usage
    .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168
                            │
                            ├─── No RC4/DES in logs? ────► Low priority
                            │
                            └─── Active RC4/DES usage detected
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 3: Detailed Investigation (30 minutes)                │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
    Get manual validation guidance & export results
    .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults -IncludeGuidance
                            │
                            ▼
    Review specific accounts/computers using RC4/DES
    Identify: Applications, Service Accounts, Legacy Systems
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 4: Remediation Planning (varies)                      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
    For DCs:  Update GPO to enforce AES-only
    For Trusts: Set msDS-SupportedEncryptionTypes to 0x18 (AES)
    For Apps: Work with vendors for AES support
    For Legacy: Plan migration or containment strategy
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Phase 5: Implement & Validate (ongoing)                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
    Re-run assessment after each change
    .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults
                            │
                            ▼
    Compare before/after results
    .\Compare-Assessments.ps1 -BaselineFile before.json -CurrentFile after.json
                            │
                            ▼
    Monitor event logs for 30+ days to ensure no RC4/DES usage
                            │
                            └─── Ready for Windows Server 2025
```

### Quick Decision Tree

**Start Here:** What's your goal?

```
┌── Single Domain or Entire Forest? ─────────────────────────────────────┐
│                                                                        │
├─► Single Domain: Use RC4_DES_Assessment.ps1                            │
│   └─► Quick Scan: .\RC4_DES_Assessment.ps1                             │
│   └─► With Events: .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs          │
│   └─► Child Domain: .\RC4_DES_Assessment.ps1 -Domain child.contoso.com │
│                                                                        │
└─► Entire Forest: Use Assess-ADForest.ps1                               │
    └─► Quick Scan: .\Assess-ADForest.ps1                                │
    └─► With Events: .\Assess-ADForest.ps1 -AnalyzeEventLogs             │
    └─► Parallel (PS7+): .\Assess-ADForest.ps1 -Parallel                 │
    └─► Export Results: .\Assess-ADForest.ps1 -ExportResults             │
└────────────────────────────────────────────────────────────────────────┘

Do you need a quick health check?
└─► Yes: .\RC4_DES_Assessment.ps1 -QuickScan
    └─► Runtime: ~30 seconds
    └─► Shows: DC/GPO/Trust configuration

Are you preparing for Windows Server 2025?
└─► Yes: .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168
    └─► Runtime: ~5 minutes
    └─► Shows: Actual RC4/DES usage over 7 days
    └─► Critical: Must show ZERO RC4 usage before upgrading

Do you have RC4/DES issues to investigate?
└─► Yes: .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -IncludeGuidance
    └─► Runtime: ~5 minutes
    └─► Shows: Which accounts/computers using weak encryption
    └─► Provides: Splunk queries, manual validation steps

Need to track progress over time?
└─► Yes: 
    1. .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults
    2. Make changes
    3. .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults
    4. .\Compare-Assessments.ps1 -BaselineFile old.json -CurrentFile new.json

Having event log access issues?
└─► Yes: Run test script to see troubleshooting guidance
    └─► .\Test-EventLogFailureHandling.ps1 -TestScenario MixedFailures
```

### Typical Deployment Scenarios

#### Scenario 1: Small Environment (< 10 DCs, < 1,000 computers)

**Week 1: Initial Assessment**
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168 -ExportResults -IncludeGuidance
```
- Review all findings
- Export for baseline
- Read manual validation guidance

**Week 2-3: Remediation**
- Fix DC/Trust configurations
- Address any RC4/DES usage found in event logs
- Re-run assessment after each fix

**Week 4: Validation**
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168 -ExportResults
.\Compare-Assessments.ps1 -BaselineFile week1.json -CurrentFile week4.json -ShowDetails
```
- Verify no RC4/DES usage
- Document remediation

#### Scenario 2: Large Enterprise (100+ DCs, 50,000+ computers)

**Month 1: Discovery Phase**
```powershell
# Week 1: Quick scan entire forest
.\Assess-ADForest.ps1 -ExportResults

# Week 2-4: Deep dive per domain (parallel processing)
.\Assess-ADForest.ps1 -AnalyzeEventLogs -EventLogHours 720 -ExportResults -Parallel -MaxParallelDomains 5
```
- Identify high-risk domains from forest summary
- Review per-domain JSON exports for detailed findings
- Map RC4/DES usage to business applications

**Month 2-3: Phased Remediation**
- Start with least critical domains
- Fix DC/GPO configurations first
- Address application-specific RC4 usage

**Month 4-6: Continuous Monitoring**
```powershell
# Weekly automated assessments
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168 -ExportResults

# Monthly comparison
.\Compare-Assessments.ps1 -BaselineFile baseline.json -CurrentFile current.json
```

#### Scenario 3: Multi-Domain Forest

**Challenge:** Assessing multiple domains efficiently

**Solution: Use Forest-Wide Assessment**
```powershell
# Quick forest scan (all domains, config only)
.\Assess-ADForest.ps1 -ExportResults

# Full forest assessment with event logs
.\Assess-ADForest.ps1 -AnalyzeEventLogs -EventLogHours 168 -ExportResults

# Parallel processing for faster completion (PowerShell 7+)
.\Assess-ADForest.ps1 -Parallel -MaxParallelDomains 5 -AnalyzeEventLogs -ExportResults
```

**Forest Assessment Benefits:**
- ✅ Automatic domain discovery
- ✅ Per-domain results exported individually
- ✅ Forest-wide summary with aggregated status
- ✅ Parallel processing support (PS 7+)
- ✅ Single consolidated view of entire forest

**Output Files:**
- `Forest_Assessment_<forestname>_<timestamp>.json` - Forest summary
- `Forest_Assessment_<forestname>_<timestamp>.csv` - Per-domain status
- `DES_RC4_Assessment_<domain>_<timestamp>.json` - Individual domain results (one per domain)

**Reviewing Results:**
```powershell
# Forest-wide status
Get-Content .\Forest_Assessment_contoso_com_20250117.json | ConvertFrom-Json | Select-Object OverallStatus, CriticalIssues, Warnings

# Per-domain comparison
.\Compare-Assessments.ps1 -BaselineFile .\DES_RC4_Assessment_domain1_20250101.json -CurrentFile .\DES_RC4_Assessment_domain1_20250117.json
```

---

## Practical Workflow Examples

### Example 1: Single Domain - Quick Health Check

**Goal:** Verify your domain is ready for Windows Server 2025

```powershell
# Step 1: Quick configuration scan
PS> .\RC4_DES_Assessment.ps1 -QuickScan

# Output shows:
# ✅ Domain Controllers are configured for AES encryption via GPO
# ✅ Trusts use AES by default
# ✅ No DES/RC4 usage detected - environment is secure

# Result: Ready to proceed with Server 2025 upgrade
```

**Time:** 30 seconds | **Risk Level:** Low

---

### Example 2: Single Domain - Deep Analysis with Event Logs

**Goal:** Find any hidden RC4/DES usage before migration

```powershell
# Step 1: Analyze 30 days of event logs
PS> .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 720 -ExportResults

# Script will:
# 1. Auto-discover DC: contoso.com (using DC: DC01.contoso.com)
# 2. Query ALL DCs in domain for event logs
# 3. Show detailed progress:
#    • Querying DC01.contoso.com...
#      ✓ Retrieved 15,234 events from DC01.contoso.com
#    • Querying DC02.contoso.com...
#      ✓ Retrieved 12,456 events from DC02.contoso.com
#    • Querying DC03.contoso.com...
#      ✗ RPC/Network error on DC03.contoso.com
#      Both WinRM (5985) and RPC (135) failed. Check firewall or run locally on DC

# Step 2: Review findings
# Output shows:
# ⚠ RC4 tickets detected in active use!
#   Unique accounts using RC4: 3
#   RC4 accounts:
#     - LEGACY-APP$
#     - SQL-SERVICE
#     - OLD-SERVER$

# Step 3: Export created
# Files: DES_RC4_Assessment_contoso_com_20250103_140523.json
#        DES_RC4_Assessment_contoso_com_20250103_140523.csv
```

**Time:** 3-5 minutes | **Action Required:** Investigate 3 RC4 accounts

---

### Example 3: Multi-Domain Forest - Complete Assessment

**Goal:** Assess entire forest with 5 domains efficiently

```powershell
# Step 1: Discover all domains and assess
PS> .\Assess-ADForest.ps1 -AnalyzeEventLogs -ExportResults -Parallel -MaxParallelDomains 3

# Output shows forest structure:
# Forest Information:
#   Name: contoso.com
#   Domains: 5
#
# Domains to assess:
#   • contoso.com (root)
#   • us.contoso.com
#   • emea.contoso.com
#   • apac.contoso.com
#   • labs.contoso.com

# For each domain, script will:
# 1. Discover specific DC in that domain
# 2. Query all DCs for event logs
# 3. Show detailed DC-level results

# Example output for child domain:
# Assessing Domain: labs.contoso.com
#   Discovering Domain Controller for labs.contoso.com...
#   Using DC: DC01.labs.contoso.com
#
#   Targeting server: DC01.labs.contoso.com
#   Querying event logs from 3 Domain Controller(s) in labs.contoso.com
#     • Querying DC01.labs.contoso.com...
#       ✓ Retrieved 8,234 events from DC01.labs.contoso.com
#     • Querying DC02.labs.contoso.com...
#       ✗ Cannot reach DC02.labs.contoso.com - skipping
#       Network unreachable - ping failed
#     • Querying DC03.labs.contoso.com...
#       ✓ Retrieved 7,891 events from DC03.labs.contoso.com

# Step 2: Review forest-wide summary
# Forest-Wide Assessment Summary
# Domain Status Summary:
#   • Total Domains: 5
#   • Healthy: 3
#   • Warnings: 2
#   • Critical: 0
#
# Per-Domain Results:
#   ✓ contoso.com: OK
#   ⚠ us.contoso.com: WARNING
#   ✓ emea.contoso.com: OK
#   ⚠ apac.contoso.com: WARNING
#   ✓ labs.contoso.com: OK

# Step 3: Investigate warnings
PS> Get-Content .\DES_RC4_Assessment_us_contoso_com_20250103.json | ConvertFrom-Json | 
    Select-Object -ExpandProperty EventLogs | 
    Select-Object RC4Accounts

# RC4Accounts
# -----------
# {APP-SERVER-01$, LEGACY-DB$}
```

**Time:** 10-15 minutes (parallel) | **Domains Needing Attention:** 2 of 5

---

### Example 4: Troubleshooting Child Domain Access

**Goal:** Assess child domain when auto-discovery fails

```powershell
# Problem: Auto-discovery failing
PS> .\RC4_DES_Assessment.ps1 -Domain labs.contoso.com -AnalyzeEventLogs

# Output shows:
# ⚠ Could not auto-discover DC for domain 'labs.contoso.com', using domain name directly
#   Error: The specified domain either does not exist or could not be contacted
#   Tip: Use -Server parameter to specify a specific DC if the domain is unreachable
# ❌ Failed to contact Domain Controller 'labs.contoso.com': Unable to contact the server...

# Solution: Specify a known DC in the child domain
PS> .\RC4_DES_Assessment.ps1 -Server DC01.labs.contoso.com -AnalyzeEventLogs

# Output shows:
# ℹ️  Targeting server: DC01.labs.contoso.com
# ✅ Successfully connected to DC01.labs.contoso.com
# ℹ️  Querying event logs from 3 Domain Controller(s) in labs.contoso.com
#     • Querying DC01.labs.contoso.com...
#       ✓ Retrieved 5,123 events from DC01.labs.contoso.com
#     • Querying DC02.labs.contoso.com...
#       ✓ Retrieved 4,987 events from DC02.labs.contoso.com
```

**Time:** 3-5 minutes | **Key Learning:** Use `-Server` for child domains with connectivity issues

---

### Example 5: Tracking Remediation Progress

**Goal:** Validate RC4 removal over time

```powershell
# Week 1: Baseline assessment
PS> .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168 -ExportResults
# Result: 
#   RC4 Tickets: 234
#   RC4 Accounts: 5 (LEGACY-APP$, SQL-SERVICE, OLD-SERVER$, APP01$, TEST-VM$)
# File: DES_RC4_Assessment_contoso_com_20250101_100000.json

# Week 2: After removing RC4 from 3 accounts
PS> .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168 -ExportResults
# Result:
#   RC4 Tickets: 67
#   RC4 Accounts: 2 (LEGACY-APP$, TEST-VM$)
# File: DES_RC4_Assessment_contoso_com_20250108_100000.json

# Compare progress
PS> .\Compare-Assessments.ps1 `
    -BaselineFile DES_RC4_Assessment_contoso_com_20250101_100000.json `
    -CurrentFile DES_RC4_Assessment_contoso_com_20250108_100000.json `
    -ShowDetails

# Output shows:
# Assessment Comparison
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Baseline: 2025-01-01 10:00:00
# Current:  2025-01-08 10:00:00
#
# Event Log Analysis Changes:
#   RC4 Tickets:  234 → 67 (✓ 71% reduction)
#   RC4 Accounts: 5 → 2 (✓ 60% reduction)
#   
#   Improvements:
#     ✓ SQL-SERVICE: No longer using RC4
#     ✓ OLD-SERVER$: No longer using RC4
#     ✓ APP01$: No longer using RC4
#   
#   Remaining Issues:
#     ⚠ LEGACY-APP$: Still using RC4 (67 tickets)
#     ⚠ TEST-VM$: Still using RC4 (new detection)
```

**Time:** 5 minutes per assessment | **Progress:** 71% reduction in RC4 usage

---

### Example 6: Event Log Access Troubleshooting

**Goal:** Diagnose and fix event log connectivity issues

```powershell
# Problem: Some DCs not accessible
PS> .\RC4_DES_Assessment.ps1 -Domain contoso.com -AnalyzeEventLogs

# Output shows mixed results:
# Querying event logs from 5 Domain Controller(s) in contoso.com
#   • Querying DC01.contoso.com...
#     ✓ Retrieved 12,345 events from DC01.contoso.com
#   • Querying DC02.contoso.com...
#     ✗ RPC/Network error on DC02.contoso.com
#     Both WinRM (5985) and RPC (135) failed. Check firewall or run locally on DC
#   • Querying DC03.contoso.com...
#     ✗ Access denied on DC03.contoso.com
#     Ensure you have Event Log Readers permissions or are Domain Admin
#   • Querying DC04.contoso.com...
#     ✗ Cannot reach DC04.contoso.com - skipping
#     Network unreachable - ping failed
#   • Querying DC05.contoso.com...
#     ✓ Retrieved 11,234 events from DC05.contoso.com
#
# Troubleshooting Summary:
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ⚠  Event Log Query Failures:
# 3 Domain Controller(s) could not be queried for event logs
#
#   • DC02.contoso.com: RPC server unavailable
#   • DC03.contoso.com: Access is denied
#   • DC04.contoso.com: Network unreachable - ping failed
#
# Resolution Options:
#   Option 1: Enable WinRM (Recommended)
#     Run on each failed DC: Enable-PSRemoting -Force
#
#   Option 2: Configure Firewall
#     Allow WinRM: TCP 5985, 5986
#     Allow RPC: TCP 135 + 49152-65535
#
#   Option 3: Run Script Locally on DCs
#     Copy script to DC02, DC03, DC04 and run locally
#
#   Option 4: Verify Permissions
#     Add-ADGroupMember -Identity 'Event Log Readers' -Members 'YourAccount'

# Fix DC02: Enable WinRM
PS> Invoke-Command -ComputerName DC02.contoso.com -ScriptBlock { Enable-PSRemoting -Force }

# Fix DC03: Add permissions
PS> Add-ADGroupMember -Identity 'Event Log Readers' -Members 'AdminAccount'

# Re-run assessment
PS> .\RC4_DES_Assessment.ps1 -Domain contoso.com -AnalyzeEventLogs
# Now all 5 DCs accessible ✓
```

**Time:** 10 minutes troubleshooting + 3 minutes retest | **Result:** All DCs now accessible

---

## Usage

### Single Domain Assessment

#### Quick Scan (Default)
```powershell
.\RC4_DES_Assessment.ps1
```
Fast assessment of DC, GPO, and trust configuration.

#### Full Assessment with Event Logs
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 48
```
Includes 48 hours of event log analysis for actual DES/RC4 usage.

#### Cross-Domain Assessment
```powershell
.\RC4_DES_Assessment.ps1 -Domain child.contoso.com -AnalyzeEventLogs
```

#### With Export and Guidance
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults -IncludeGuidance
```
Full assessment with JSON/CSV export and manual validation guidance.

### Forest-Wide Assessment

#### Quick Forest Scan
```powershell
.\Assess-ADForest.ps1
```
Assess all domains in current forest (configuration only, fast).

#### Full Forest Assessment with Event Logs
```powershell
.\Assess-ADForest.ps1 -AnalyzeEventLogs -ExportResults
```
Complete forest assessment with event log analysis and per-domain exports.

#### Parallel Processing (PowerShell 7+)
```powershell
.\Assess-ADForest.ps1 -Parallel -MaxParallelDomains 5 -AnalyzeEventLogs
```
Assess up to 5 domains concurrently for faster completion.

#### Specific Forest with Extended Analysis
```powershell
.\Assess-ADForest.ps1 -ForestName contoso.com -AnalyzeEventLogs -EventLogHours 168 -ExportResults
```
Assess specific forest with 7 days of event logs across all domains.

### Comparing Assessments Over Time
```powershell
.\Compare-Assessments.ps1 -BaselineFile old.json -CurrentFile new.json -ShowDetails
```
Compare two assessment results to track improvements, identify new issues, and validate remediation efforts.

### RC4_DES_Assessment.ps1 Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Domain` | Target domain to assess | Current domain |
| `-Server` | Specific DC to query | Any available DC |
| `-AnalyzeEventLogs` | Analyze event logs for actual usage | Not enabled |
| `-EventLogHours` | Hours of events to analyze (1-168) | 24 |
| `-ExportResults` | Export to JSON and CSV | Not enabled |
| `-IncludeGuidance` | Show manual validation guidance | Not enabled |
| `-QuickScan` | Quick scan only (explicit) | Default mode |

### Assess-ADForest.ps1 Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-ForestName` | Target AD forest to assess | Current forest |
| `-AnalyzeEventLogs` | Include event log analysis per domain | Not enabled |
| `-EventLogHours` | Hours of events to analyze (1-168) | 24 |
| `-ExportResults` | Export per-domain and forest summary | Not enabled |
| `-Parallel` | Process domains in parallel (PS 7+) | Not enabled |
| `-MaxParallelDomains` | Max concurrent domains (1-10) | 3 |

## Understanding the Results

### Reading the Assessment Output

The script provides color-coded findings to help you quickly identify issues:

- **✅ Green (OK)**: Secure configuration, no action needed
- **⚠️ Yellow (WARNING)**: RC4 detected, should remediate before Server 2025
- **❌ Red (CRITICAL)**: DES detected or active RC4 usage - immediate action required
- **ℹ️ Cyan (INFO)**: Informational messages, context

### Domain Controller Assessment

**Scenario 1: All DCs Properly Configured via GPO**
```
Domain Controller Encryption Configuration
────────────────────────────────────────────────────────────────
ℹ️  Analyzing domain: contoso.com
ℹ️  Found 5 Domain Controller(s)

  Checking GPO Kerberos encryption policy...
✅ GPO 'Default Domain Controllers Policy' configures Kerberos encryption
   Encryption types: AES128-HMAC, AES256-HMAC

ℹ️  Domain Controller Summary:
  • Total DCs: 5
  • AES Configured: 0
  • RC4 Configured: 0
  • DES Configured: 0
  • Not Configured (GPO Inherited): 5

  Individual DC Status:
    • DC01: Not Configured (Inherits from GPO)
    • DC02: Not Configured (Inherits from GPO)
    • DC03: Not Configured (Inherits from GPO)
    • DC04: Not Configured (Inherits from GPO)
    • DC05: Not Configured (Inherits from GPO)

✅ Domain Controllers are configured for AES encryption via GPO
ℹ️  5 DC(s) inherit AES settings from GPO (this is normal)
```

**What it means:** Perfect configuration! DCs inherit AES from GPO, which is the recommended approach. No action needed.

---

**Scenario 2: Mixed Configuration with RC4**
```
Domain Controller Encryption Configuration
────────────────────────────────────────────────────────────────
ℹ️  Domain Controller Summary:
  • Total DCs: 3
  • AES Configured: 2
  • RC4 Configured: 1
  • DES Configured: 0
  • Not Configured (GPO Inherited): 0

  Individual DC Status:
    • DC01: AES Configured
      Types: AES128-HMAC, AES256-HMAC
    • DC02: AES Configured
      Types: AES128-HMAC, AES256-HMAC
    • DC03: AES Configured + RC4
      Types: AES128-HMAC, AES256-HMAC, RC4-HMAC

⚠️  1 DC(s) have RC4 encryption enabled
```

**What it means:** DC03 has RC4 still enabled alongside AES. While not critical, RC4 should be removed before Windows Server 2025.

**Action:** Remove RC4 from DC03:
```powershell
Set-ADComputer DC03 -Replace @{'msDS-SupportedEncryptionTypes'=24}
# 24 = 0x18 = AES128 + AES256
```

---

**Scenario 3: CRITICAL - DES Detected**
```
  • DES Configured: 1

  Individual DC Status:
    • OLD-DC: DES Only
      Types: DES-CBC-CRC, DES-CBC-MD5

❌ 1 DC(s) have DES encryption enabled - immediate remediation required
```

**What it means:** OLD-DC only supports DES encryption - critically insecure!

**Action:** URGENT - Upgrade or decommission this DC immediately. DES is broken encryption.

### Trust Assessment

**Scenario 1: Post-Nov 2022 Secure Default**
```
Trust Encryption Assessment (Post-November 2022 Logic)
────────────────────────────────────────────────────────────────
ℹ️  Found 2 trust(s)
✅ Trust 'partner.contoso.com': Uses AES by default (msDS-SupportedEncryptionTypes not set)
✅ Trust 'external.com': AES explicitly configured

ℹ️  Trust Assessment Summary:
  • Total Trusts: 2
  • AES Default (not set): 1
  • AES Explicit: 1
  • RC4 Risk: 0
  • DES Risk: 0

  📘 Post-November 2022 Update:
  When msDS-SupportedEncryptionTypes is not set (0 or empty) on trusts,
  they default to AES encryption. No action needed for these trusts.
```

**What it means:** Both trusts are secure. The first trust uses the new default (AES), the second has explicit AES configuration.

---

**Scenario 2: Trust with RC4 Enabled**
```
⚠️  Trust 'legacy.external.com': AES configured but RC4 also enabled
    Encryption: AES128-HMAC, AES256-HMAC, RC4-HMAC

  • RC4 Risk: 1
```

**What it means:** Trust has AES but RC4 is still allowed. Should clean this up.

**Action:** Remove RC4 from trust:
```powershell
# Get the trust
$trust = Get-ADTrust -Identity "legacy.external.com"

# Set to AES only (0x18 = AES128 + AES256)
Set-ADTrust -Identity $trust -Replace @{'msDS-SupportedEncryptionTypes'=24}
```

### Event Log Analysis

**Scenario 1: Clean Environment**
```
Event Log Analysis - Actual DES/RC4 Usage
────────────────────────────────────────────────────────────────
ℹ️  Analyzing last 24 hours of Kerberos ticket events
  Time range: 2025-12-02 10:00 to 2025-12-03 10:00
ℹ️  Querying event logs from 3 Domain Controller(s)...
  Note: Using WinRM (PowerShell Remoting) for event log queries
  • Querying DC01...
  • Querying DC02...
  • Querying DC03...

ℹ️  Event Log Analysis Results:
  • Events Analyzed: 28,543
  • AES Tickets: 28,543
  • RC4 Tickets: 0
  • DES Tickets: 0

✅ No RC4 tickets detected in last 24 hours
✅ No DES tickets detected in last 24 hours
```

**What it means:** Perfect! No actual RC4/DES usage detected. Environment is ready for Windows Server 2025.

---

**Scenario 2: RC4 Usage Detected**
```
ℹ️  Event Log Analysis Results:
  • Events Analyzed: 15,432
  • AES Tickets: 15,430
  • RC4 Tickets: 2
  • DES Tickets: 0

❌ RC4 tickets detected in active use!
  Unique accounts using RC4: 2
  RC4 accounts:
    - LEGACY-APP$
    - SQL-SERVER-2008$
```

**What it means:** Two computer accounts are actively requesting RC4 tickets despite DCs supporting AES. These systems need investigation.

**Action:**
1. Check why these systems are using RC4:
   ```powershell
   Get-ADComputer LEGACY-APP -Properties msDS-SupportedEncryptionTypes
   Get-ADComputer SQL-SERVER-2008 -Properties msDS-SupportedEncryptionTypes
   ```

2. Investigate the applications:
   - LEGACY-APP$: May be running old software that doesn't support AES
   - SQL-SERVER-2008$: SQL Server 2008 is EOL, needs upgrade

3. Plan remediation:
   - Upgrade to newer OS/applications that support AES
   - Or isolate these systems (not recommended long-term)

---

**Scenario 3: Event Log Access Issues**
```
Event Log Analysis - Actual DES/RC4 Usage
────────────────────────────────────────────────────────────────
ℹ️  Querying event logs from 3 Domain Controller(s)...
  • Querying DC01...
    ⚠️  RPC/Network error on DC01
       Both WinRM (5985) and RPC (135) failed. Check firewall rules

  • Querying DC02...
    ✓ Successfully queried DC02
  
  • Querying DC03...
    ⚠️  Access denied on DC03
       Ensure you have Event Log Readers permissions or are Domain Admin

ℹ️  Event Log Analysis Results:
  • Events Analyzed: 4,231
  • AES Tickets: 4,229
  • RC4 Tickets: 2
  • DES Tickets: 0

  ⚠️  Event Log Query Failures:
  2 Domain Controller(s) could not be queried for event logs

  • DC01: The RPC server is unavailable. (Exception from HRESULT: 0x800706BA)
  • DC03: Access is denied. Attempted to perform an unauthorized operation.

  🔧 How to fix remote event log access issues:
  [... detailed troubleshooting guidance displayed ...]
```

**What it means:** Only partial data collected due to access issues. Results may be incomplete.

**Action:** Follow the displayed troubleshooting guidance to:
- Enable WinRM on failed DCs
- Configure firewall rules
- Verify permissions
- Or run script locally on DCs

### Overall Assessment Summary

**Scenario 1: Fully Secure**
```
Overall Security Assessment
────────────────────────────────────────────────────────────────
✅ No DES/RC4 usage detected - environment is secure

Assessment Complete
================================================================================

📊 Summary:
  • Domain: contoso.com
  • Assessment Date: 2025-12-03 10:30:00
  • Overall Status: OK

  💡 For complete assessment, run with -AnalyzeEventLogs to detect actual DES/RC4 usage
```

---

**Scenario 2: Warnings Detected**
```
Overall Security Assessment
────────────────────────────────────────────────────────────────
⚠️  Security warnings detected - remediation recommended

  Recommendations:
    • WARNING: Remove RC4 encryption from 1 Domain Controller(s)
    • WARNING: 1 trust(s) have RC4 enabled

  Overall Status: WARNING
```

---

**Scenario 3: Critical Issues**
```
Overall Security Assessment
────────────────────────────────────────────────────────────────
❌ Critical security issues detected requiring immediate attention

  Recommendations:
    • CRITICAL: Remove DES encryption from 1 Domain Controller(s)
    • CRITICAL: RC4 tickets detected in event logs - active usage detected
    • WARNING: Remove RC4 encryption from 2 Domain Controller(s)

  ⚠️  Note: Event log data is incomplete due to 2 DC(s) being inaccessible
     Review the detailed troubleshooting guidance in the Event Log Analysis section above

  Overall Status: CRITICAL
```

**What it means:** Immediate action required. DES usage and active RC4 tickets must be addressed before Windows Server 2025 migration.

## What This Tool Does NOT Check

### Computer Objects (Intentionally Excluded)

**Why:** In large environments (100,000+ computers), enumerating all computer objects takes 5+ hours and provides little value.

**Post-Nov 2022 Reality:** If DCs have AES configured, computers inherit AES even if their `msDS-SupportedEncryptionTypes` is empty.

**When to Check Manually:**
- Event logs show RC4 tickets (0x17)
- Investigating specific problematic computers
- Compliance requirement for explicit configuration

**How to Check Manually:**
```powershell
# Check specific computer
Get-ADComputer "COMPUTERNAME" -Properties msDS-SupportedEncryptionTypes

# Find computers with RC4 explicitly set
Get-ADComputer -Filter 'msDS-SupportedEncryptionTypes -band 4' -Properties msDS-SupportedEncryptionTypes
```

### Service Accounts (Use Event Logs Instead)

**Why:** Service account SPN enumeration is slow and doesn't show actual usage.

**Better Approach:** Event log analysis shows which accounts actually request RC4/DES tickets.

### KRBTGT Password Age

**Why:** This is a general AD hygiene issue, not specific to DES/RC4 assessment.

**Recommendation:** Use dedicated KRBTGT rotation tools.

## Event Log Monitoring Setup

### Enable Kerberos Auditing

Group Policy path:
```
Computer Configuration
  > Policies
    > Windows Settings
      > Security Settings
        > Advanced Audit Policy Configuration
          > Audit Policies
            > Account Logon
```

Enable:
- ✅ Audit Kerberos Authentication Service: Success and Failure
- ✅ Audit Kerberos Service Ticket Operations: Success and Failure

### Splunk Query for RC4 Detection

```spl
index=windows EventCode=4768 OR EventCode=4769 
| eval EncType=case(
    TicketEncryptionType="0x17", "RC4",
    TicketEncryptionType="0x3", "DES",
    TicketEncryptionType="0x1", "DES",
    TicketEncryptionType="0x11", "AES128",
    TicketEncryptionType="0x12", "AES256",
    1=1, "Unknown"
  )
| where EncType="RC4" OR EncType="DES"
| stats count by TargetUserName, EncType, ComputerName
| sort -count
```

### Event ID Reference

| Event ID | Description | Key Field |
|----------|-------------|-----------|
| 4768 | TGT Request | `TicketEncryptionType` |
| 4769 | Service Ticket Request | `TicketEncryptionType` |

**Encryption Type Values:**
- `0x1` or `0x3`: DES (CRITICAL)
- `0x17`: RC4-HMAC (WARNING)
- `0x11` or `0x12`: AES (GOOD)

### Recommended Approach

1. **Initial Assessment:** Use v2.0 for fast, accurate results
2. **Event Monitoring:** Set up continuous monitoring based on v2.0 guidance
3. **Remediation:** Address actual findings from event logs
4. **Compliance:** If required to scan all computers, use v1.0 selectively

## Troubleshooting

### Event Log Access Issues (NEW in v2.0.1)

The script now provides comprehensive troubleshooting guidance when it cannot access event logs on remote DCs.

**Common Issues:**
- **RPC Server Unavailable**: Firewall blocking RPC ports (135, 49152-65535)
- **WinRM Errors**: PowerShell Remoting not enabled on DCs
- **Access Denied**: Insufficient permissions to read event logs
- **Network Path Not Found**: DNS resolution or network connectivity issues

**Automatic Troubleshooting Summary:**

When event log queries fail, the script displays:
1. Which DCs failed and why
2. Four detailed resolution options:
   - Enable WinRM (recommended)
   - Configure firewall for RPC
   - Run script locally on DC
   - Verify permissions

See sample output above for the complete troubleshooting guidance.

**Testing Error Handling:**

Use the included test script to verify error handling without actual network issues:

```powershell
# Test RPC failures
.\Test-EventLogFailureHandling.ps1 -TestScenario RPCFailure

# Test mixed scenarios (most realistic)
.\Test-EventLogFailureHandling.ps1 -TestScenario MixedFailures

# Test all successful (control test)
.\Test-EventLogFailureHandling.ps1 -TestScenario AllSuccess
```

### "No events analyzed"

**Cause:** Event log access denied or auditing not enabled.

**Solution:**
1. Verify Kerberos auditing is enabled (see setup section)
2. Check event log permissions on DCs
3. Ensure firewall allows WinRM (event log queries)

### "Could not retrieve GPO information"

**Cause:** Cross-domain authentication issues.

**Solution:**
```powershell
# Specify a DC in the target domain
.\RC4_DES_Assessment.ps1 -Domain child.contoso.com -Server DC01.child.contoso.com
```

### "Access denied" errors

**Cause:** Insufficient permissions.

**Requirements:**
- Domain Users (for read-only assessment)
- Event Log Readers (for event analysis)
- Domain Admins (for full GPO analysis)

## Windows Server 2025 Preparation

Windows Server 2025 **completely disables RC4 fallback**.

### Preparation Steps

1. **Run v2.0 with Event Analysis:**
   ```powershell
   .\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168
   ```
   Look for ANY RC4 usage over the past week.

2. **Set Up Continuous Monitoring:**
   - Configure Splunk/SIEM alerts for RC4 events
   - Monitor for 30+ days to catch sporadic usage

3. **Identify Problem Systems:**
   - Systems that can't handle AES
   - Legacy applications requiring RC4
   - Plan upgrades or exceptions

4. **Lab Testing:**
   - Deploy Server 2025 in test environment
   - Verify no RC4 usage in production first

5. **Gradual Rollout:**
   - Upgrade DCs one at a time
   - Monitor event logs after each upgrade
   - Have rollback plan ready

## Export and Comparison Workflow

### Step 1: Create Baseline Assessment

Run initial assessment and export results:

```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults
```

**Output files:**
- `DES_RC4_Assessment_contoso_com_20251127_154530.json` (complete data)
- `DES_RC4_Assessment_contoso_com_20251127_154530.csv` (summary table)

### Step 2: Implement Remediation

Address identified issues:
- Remove RC4/DES from DCs
- Configure trusts with explicit AES
- Upgrade/replace systems using weak encryption

### Step 3: Run Follow-up Assessment

After remediation, run another assessment:

```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults
```

### Step 4: Compare Results

Use the comparison script to track progress:

```powershell
.\Compare-Assessments.ps1 `
  -BaselineFile .\DES_RC4_Assessment_contoso_com_20251127_154530.json `
  -CurrentFile .\DES_RC4_Assessment_contoso_com_20251215_093000.json `
  -ShowDetails
```

**Comparison output shows:**
- ↓ Improvements (green) - fewer RC4/DES configurations
- ↑ Degradations (red) - new RC4/DES detections
- → Unchanged (gray) - no change
- Overall security posture improvement/degradation summary

### Export Format

#### JSON Export
Complete assessment data in structured format for automation/integration:

```json
{
  "Domain": "contoso.com",
  "AssessmentDate": "2025-11-27T15:45:30",
  "OverallStatus": "WARNING",
  "DomainControllers": {
    "TotalDCs": 5,
    "AESConfigured": 4,
    "RC4Configured": 1,
    "DESConfigured": 0,
    "Details": [...]
  },
  "Trusts": {...},
  "EventLogs": {...},
  "Recommendations": [...]
}
```

#### CSV Export
Simplified tabular format for Excel analysis:

| Type | Name | Status | EncryptionTypes | EncryptionValue |
|------|------|--------|-----------------|-----------------|
| Domain Controller | DC01 | AES Configured | AES128, AES256 | 24 |
| Trust | partner.com | AES (Default) | Not Set (Default) | 0 |

### Typical Monitoring Schedule

**Baseline Assessment:**
- Before any changes
- Export and archive results

**Monthly Reviews:**
```powershell
.\RC4_DES_Assessment.ps1 -QuickScan -ExportResults
```

**Quarterly Deep Analysis:**
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168 -ExportResults
.\Compare-Assessments.ps1 -BaselineFile baseline.json -CurrentFile current.json -ShowDetails
```

**Pre-Windows Server 2025 Migration:**
```powershell
# Run weekly for 4-8 weeks to capture all usage patterns
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168 -ExportResults
```

## Support and Feedback

### Reporting Issues

Include:
- PowerShell version: `$PSVersionTable.PSVersion`
- AD module version: `(Get-Module ActiveDirectory).Version`
- Error messages and stack trace
- Anonymized environment details (forest size, DC count)

### Feature Requests

Based on real-world usage, especially:
- Integration with existing monitoring tools
- Additional cross-domain scenarios
- Custom reporting formats

## License

Same as original RC4_AD_SCAN project.

## Credits

- Original RC4_AD_SCAN v1.0 concept and implementation
- Customer feedback and real-world testing (Thanks to Simon Arnreiter)
- Microsoft Kerberos security documentation team
- Active Directory security community

## Sample Output

### Quick Scan Output

```
================================================================================
DES/RC4 Kerberos Encryption Assessment v2.0
================================================================================

Domain Controller Encryption Configuration
────────────────────────────────────────────────────────────────
ℹ️  Analyzing domain: contoso.com
ℹ️  Found 3 Domain Controller(s)

ℹ️  Domain Controller Summary:
  • Total DCs: 3
  • AES Configured: 3
  • RC4 Configured: 0
  • DES Configured: 0
  • Not Configured (GPO Inherited): 0

  Individual DC Status:
    • DC01: AES Configured
      Types: AES128-HMAC, AES256-HMAC
    • DC02: AES Configured
      Types: AES128-HMAC, AES256-HMAC
    • DC03: AES Configured
      Types: AES128-HMAC, AES256-HMAC

✅ All Domain Controllers have AES encryption configured


Trust Encryption Assessment (Post-November 2022 Logic)
────────────────────────────────────────────────────────────────
ℹ️  Found 2 trust(s)
✅ Trust 'partner.contoso.com': Uses AES by default (msDS-SupportedEncryptionTypes not set)
✅ Trust 'external.com': AES explicitly configured

ℹ️  Trust Assessment Summary:
  • Total Trusts: 2
  • AES Default (not set): 1
  • AES Explicit: 1
  • RC4 Risk: 0
  • DES Risk: 0

  📘 Post-November 2022 Update:
  When msDS-SupportedEncryptionTypes is not set (0 or empty) on trusts,
  they default to AES encryption. No action needed for these trusts.


Overall Security Assessment
────────────────────────────────────────────────────────────────
✅ No DES/RC4 usage detected - environment is secure

  💡 For complete assessment, run with -AnalyzeEventLogs to detect actual DES/RC4 usage


Assessment Complete
================================================================================

📊 Summary:
  • Domain: contoso.com
  • Assessment Date: 2025-12-03 14:30:00
  • Overall Status: OK
```

### Full Assessment with Event Logs

```
Event Log Analysis - Actual DES/RC4 Usage
────────────────────────────────────────────────────────────────
ℹ️  Analyzing last 24 hours of Kerberos ticket events
  Time range: 2025-12-02 14:30 to 2025-12-03 14:30
ℹ️  Querying event logs from 3 Domain Controller(s)...
  Note: Using WinRM (PowerShell Remoting) for event log queries
  If this fails, ensure WinRM is enabled on DCs: Enable-PSRemoting -Force
  • Querying DC01...
  • Querying DC02...
  • Querying DC03...

ℹ️  Event Log Analysis Results:
  • Events Analyzed: 15,432
  • AES Tickets: 15,430
  • RC4 Tickets: 2
  • DES Tickets: 0

❌ RC4 tickets detected in active use!
  Unique accounts using RC4: 2
  RC4 accounts:
    - LEGACY-APP$
    - OLD-SERVER$
✅ No DES tickets detected in last 24 hours
```

### Event Log Query Failures with Troubleshooting

```
Event Log Analysis - Actual DES/RC4 Usage
────────────────────────────────────────────────────────────────
ℹ️  Analyzing last 24 hours of Kerberos ticket events
  • Querying DC01.contoso.com...
    ⚠  RPC/Network error on DC01.contoso.com
       Both WinRM (5985) and RPC (135) failed. Check firewall rules or run locally on DC

    Troubleshooting:
    1. Enable WinRM on DC: Enable-PSRemoting -Force
    2. Or allow RPC in firewall: Port 135 + 49152-65535
    3. Or run this script directly on the DC
    4. Check permissions: Add your account to 'Event Log Readers' group

  • Querying DC02.contoso.com...
    ✓ Successfully queried DC02.contoso.com
  • Querying DC03.contoso.com...
    ⚠  Access denied on DC03.contoso.com
       Ensure you have Event Log Readers permissions or are Domain Admin

ℹ️  Event Log Analysis Results:
  • Events Analyzed: 150
  • AES Tickets: 148
  • RC4 Tickets: 2
  • DES Tickets: 0

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

  Or via Group Policy (for all DCs):
  Computer Configuration > Policies > Administrative Templates
  > Windows Components > Windows Remote Management (WinRM) > WinRM Service
  - Enable 'Allow remote server management through WinRM'
  - IPv4 filter: * (or specific IPs)

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
  Or use Domain Admin account (has all required permissions)


Overall Security Assessment
────────────────────────────────────────────────────────────────
⚠  Note: Event log data is incomplete due to 2 DC(s) being inaccessible
   Review the detailed troubleshooting guidance in the Event Log Analysis section above
```

## Version History

### v2.0.1 (Current - December 2025)
- **NEW:** Remote event log access failure tracking and troubleshooting
- **NEW:** Comprehensive end-of-assessment summary for RPC/WinRM issues
- **NEW:** Test script for validating error handling (Test-EventLogFailureHandling.ps1)
- **IMPROVED:** Child domain support with proper identity parameter handling
- **IMPROVED:** WinRM-first approach for event log queries with RPC fallback
- **IMPROVED:** UTF-8 console encoding for proper Unicode display in PowerShell 5.1
- **FIXED:** Bullet characters and Unicode symbols display correctly
- Complete rewrite based on customer feedback
- Post-November 2022 update logic
- Event log analysis for actual usage detection
- Performance optimization for large forests
- Comprehensive manual validation guidance

### v2.0 (November 2025)
- Initial v2.0 release
- Post-November 2022 update logic
- Event log analysis for actual usage detection
- Performance optimization for large forests

### v1.0 (Legacy)
- Initial implementation
- Comprehensive computer/trust/service account scanning
- Pre-November 2022 logic
