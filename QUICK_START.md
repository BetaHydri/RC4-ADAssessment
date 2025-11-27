# RC4_DES_Assessment.ps1 - Quick Start Guide

## 🎯 Testing Without Active Directory

**You can test the script RIGHT NOW without AD access!**

### Run the Test Script
```powershell
.\Test-RC4Script.ps1
```

This validates:
- ✓ Display formatting and colors work correctly
- ✓ Emoji and Unicode symbols render properly (PowerShell 5.1 compatible)
- ✓ Encryption type decoding logic (hex → encryption names)
- ✓ Event log ticket type detection
- ✓ Mock assessment report display
- ✓ All helper functions

### What the Test Covers

1. **Status Symbols** - ✓ (OK), ⚠ (WARNING), ✗ (CRITICAL), ℹ (INFO)
2. **Emojis** - 📊 📋 📚 💡 (all PowerShell 5.1 compatible)
3. **Encryption Decoding**:
   - `0x0` → Not Set (AES default post-Nov 2022)
   - `0x1` → DES (CRITICAL)
   - `0x4` → RC4 (WARNING)
   - `0x18` → AES 128+256 (GOOD)
4. **Event Log Analysis** - Ticket type detection (0x1, 0x3, 0x17, 0x11, 0x12)
5. **Report Formatting** - Headers, sections, color coding

---

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

### Phase 1: Current State Assessment (No AD Required)
```powershell
.\Test-RC4Script.ps1
```
Verify script functionality and output format.

### Phase 2: Initial AD Scan
```powershell
.\RC4_DES_Assessment.ps1 -QuickScan
```
Get baseline configuration (DCs, GPOs, Trusts).

### Phase 3: Usage Analysis
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 168
```
Analyze 7 days of event logs to detect actual DES/RC4 usage.

### Phase 4: Monitoring Setup
```powershell
.\RC4_DES_Assessment.ps1 -IncludeGuidance
```
Get Splunk queries and continuous monitoring setup.

### Phase 5: Remediation
Follow recommendations from the assessment report.

---

## 🆘 Troubleshooting

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

### Emojis not displaying correctly
**Solution**: Already fixed! Script uses `[System.Char]::ConvertFromUtf32()` for PowerShell 5.1 compatibility

### Script runs very slowly
**Solution**: Use `-QuickScan` to skip event log analysis
```powershell
.\RC4_DES_Assessment.ps1 -QuickScan
```

---

## 📚 Additional Resources

- **README_v2.md** - Comprehensive documentation
- **Test-RC4Script.ps1** - Standalone testing (no AD required)
- **Microsoft KB5021131** - Post-Nov 2022 Kerberos changes
- **Windows Server 2025** - RC4 completely disabled by default

---

## 💡 Pro Tips

1. **Start with QuickScan** - Get quick results, then add event log analysis
2. **Monitor for 30 days** - Capture monthly/quarterly activities before Server 2025 upgrade
3. **Check event logs regularly** - Weekly alerts for RC4/DES usage
4. **Export results** - Keep historical data for compliance/auditing
5. **Include guidance** - Get actionable steps for remediation and monitoring

---

## ✅ Validation Checklist

Before deploying to production:
- [ ] Test script runs without errors: `.\Test-RC4Script.ps1`
- [ ] PowerShell 5.1 syntax validated
- [ ] Emoji/Unicode symbols display correctly
- [ ] All helper functions working
- [ ] Mock assessment displays properly

When you have AD access:
- [ ] Quick scan completes successfully
- [ ] DCs detected and assessed
- [ ] GPO encryption settings retrieved
- [ ] Trusts enumerated correctly
- [ ] Event log analysis works (if using -AnalyzeEventLogs)
- [ ] Export creates JSON/CSV files (if using -ExportResults)

---

**Current Status**: ✅ Script tested and ready - waiting for AD access to perform live assessment
