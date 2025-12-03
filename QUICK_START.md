# RC4_DES_Assessment.ps1 v2.0.1 - Quick Start Guide

> **✨ New in v2.0.1:** Enhanced remote event log access troubleshooting with comprehensive guidance when RPC/WinRM issues occur.

## 🔐 Using with Active Directory

### Prerequisites
- PowerShell 5.1 or later
- Active Directory PowerShell module
- Domain Admin or equivalent permissions
- Network access to domain controllers

### Quick Scan (Fastest - No Event Logs)
```powershell
.\RC4_DES_Assessment.ps1 -QuickScan
```
**Runtime**: ~30 seconds  
**Checks**: Domain Controllers, GPOs, Trusts

### Full Assessment (Recommended)
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 24
```
**Runtime**: 2-5 minutes  
**Checks**: DCs, GPOs, Trusts + 24 hours of event logs for actual DES/RC4 usage

### With Export
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults
```
**Output**: JSON and CSV files with timestamp

### With Guidance
```powershell
.\RC4_DES_Assessment.ps1 -IncludeGuidance
```
**Shows**: Detailed manual validation steps, Splunk queries, monitoring setup

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

---

## 📊 Sample Output

### Successful Quick Scan
```
================================================================================
DES/RC4 Kerberos Encryption Assessment v2.0
================================================================================

Domain Controller Encryption Configuration
────────────────────────────────────────────────────────────────
ℹ️  Analyzing domain: contoso.com
ℹ️  Found 3 Domain Controller(s)

✅ Domain Controllers are configured for AES encryption via GPO
ℹ️  3 DC(s) inherit AES settings from GPO (this is normal)

Trust Encryption Assessment (Post-November 2022 Logic)
────────────────────────────────────────────────────────────────
ℹ️  Found 1 trust(s)
✅ Trust 'partner.com': Uses AES by default (msDS-SupportedEncryptionTypes not set)

Overall Security Assessment
────────────────────────────────────────────────────────────────
✅ No DES/RC4 usage detected - environment is secure
```

### Event Log Analysis with RC4 Detection
```
Event Log Analysis - Actual DES/RC4 Usage
────────────────────────────────────────────────────────────────
ℹ️  Analyzing last 24 hours of Kerberos ticket events
ℹ️  Querying event logs from 3 Domain Controller(s)...
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

---

## 📊 Understanding the Results

### Overall Status
- **🟢 OK** - No DES/RC4 usage detected, environment is secure
- **🟡 WARNING** - RC4 detected, should be removed (especially for Server 2025)
- **🔴 CRITICAL** - DES detected or active RC4 usage in event logs

### Domain Controllers
- **AES Configured** - DCs with AES encryption (good)
- **RC4 Configured** - DCs allowing RC4 (warning)
- **DES Configured** - DCs allowing DES (critical - remove immediately)
- **Not Configured (GPO Inherited)** - DCs getting settings from GPO (normal)

### Trusts (Post-November 2022 Logic)
- **AES Default (not set)** - Trusts with no msDS-SupportedEncryptionTypes (✓ secure)
- **AES Explicit** - Trusts with AES explicitly configured (✓ secure)
- **RC4 Risk** - Trusts with RC4 enabled (⚠ remove for Server 2025)
- **DES Risk** - Trusts with DES enabled (🔴 critical)

### Event Logs (Most Important!)
- **AES Tickets** - Kerberos tickets using AES (✓ expected)
- **RC4 Tickets** - Active RC4 usage (⚠ investigate clients)
- **DES Tickets** - Active DES usage (🔴 critical - legacy systems)

---

## 🚀 Migration Path

### Phase 1: Initial AD Scan
```powershell
.\RC4_DES_Assessment.ps1 -QuickScan
```
Get baseline configuration (DCs, GPOs, Trusts).

### Phase 2: Usage Analysis
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168
```
Analyze 7 days of event logs to detect actual DES/RC4 usage.

### Phase 3: Monitoring Setup
```powershell
.\RC4_DES_Assessment.ps1 -IncludeGuidance
```
Get Splunk queries and continuous monitoring setup.

### Phase 4: Remediation
Follow recommendations from the assessment report.

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

- **README.md** - Comprehensive documentation with sample outputs
- **Test-EventLogFailureHandling.ps1** - Test script for error handling validation
- **archive/README_v1_LEGACY.md** - Legacy v1.0 documentation (archived)
- **Microsoft KB5021131** - Post-Nov 2022 Kerberos changes
- **Windows Server 2025** - RC4 completely disabled by default

---

## 🎯 What's New in v2.0.1

### Forest-Wide Assessment (NEW!)
- **Assess-ADForest.ps1** - New script for assessing all domains in an AD forest
- **Automatic domain discovery** - Get-ADForest enumerates all domains
- **Parallel processing** - Process multiple domains concurrently (PowerShell 7+)
- **Consolidated reporting** - Forest-wide summary + per-domain exports
- **Flexible deployment** - Quick scan or full event log analysis across entire forest

### Remote Event Log Access Troubleshooting
- **Automatic failure tracking** - Script now tracks which DCs couldn't be queried
- **Comprehensive troubleshooting** - Detailed guidance for RPC/WinRM issues at end of assessment
- **Four fix options** - WinRM setup, firewall configuration, local execution, or permission fixes
- **Test script included** - Validate error handling without requiring actual failures

### Enhanced Multi-Domain Support
- **Child domain fixes** - Proper identity parameter handling for cross-domain queries
- **Better error messages** - Clear guidance when querying child domains

### PowerShell 5.1 Compatibility
- **UTF-8 encoding** - Automatic console encoding configuration
- **Unicode symbols** - Proper bullet points and status symbols in both PS 5.1 and 7

### Event Log Query Improvements
- **WinRM-first approach** - Tries PowerShell Remoting before falling back to RPC
- **Connectivity testing** - Checks DC reachability before attempting queries
- **Better error categorization** - Distinguishes between WinRM, RPC, permission, and network errors

---

## 💡 Pro Tips

1. **Start with QuickScan** - Get quick results, then add event log analysis
2. **Use Forest Assessment for multi-domain environments** - `Assess-ADForest.ps1` automates domain enumeration
3. **Enable parallel processing** - Use `-Parallel` with PowerShell 7+ for faster forest assessments
4. **Monitor for 30 days** - Capture monthly/quarterly activities before Server 2025 upgrade
5. **Check event logs regularly** - Weekly alerts for RC4/DES usage
6. **Export results** - Keep historical data for compliance/auditing
7. **Include guidance** - Get actionable steps for remediation and monitoring

---

## ✅ Validation Checklist

When you have AD access:
- [ ] Quick scan completes successfully
- [ ] DCs detected and assessed
- [ ] GPO encryption settings retrieved
- [ ] Trusts enumerated correctly
- [ ] Event log analysis works (if using -AnalyzeEventLogs)
- [ ] Export creates JSON/CSV files (if using -ExportResults)
