# DES/RC4 Kerberos Encryption Assessment v2.0

## Overview

A completely redesigned tool for assessing DES and RC4 encryption usage in Active Directory environments, addressing critical limitations discovered in v1.0 and incorporating post-November 2022 Microsoft Kerberos security updates.

## Why Version 2.0?

### Customer Feedback on v1.0

Real-world deployment revealed several critical issues:

1. **Performance**: 5.5+ hours to complete in large forests (unacceptable for production use)
2. **Confusion**: Unclear guidance on `msDS-SupportedEncryptionTypes` requirements
3. **Outdated Logic**: Pre-November 2022 trust encryption assumptions
4. **False Positives**: Flagged theoretical risks instead of actual usage
5. **Missing Validation**: No guidance for manual checks and event monitoring

### Key Improvements in v2.0

✅ **Fast Execution**: < 5 minutes vs 5+ hours  
✅ **Post-Nov 2022 Logic**: Accurate trust and computer encryption assessment  
✅ **Event-Based Analysis**: Detects actual DES/RC4 usage from Kerberos tickets  
✅ **Clear Guidance**: Actionable manual validation steps and SIEM queries  
✅ **Realistic Assessment**: No unnecessary computer object enumeration

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

## Features

### Core Scripts

1. **RC4_DES_Assessment.ps1** - Main assessment tool
2. **Test-RC4Script.ps1** - Test functionality without AD access
3. **Compare-Assessments.ps1** - Compare assessment results over time

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

## Usage

### Quick Scan (Default)
```powershell
.\RC4_DES_Assessment.ps1
```
Fast assessment of DC, GPO, and trust configuration.

### Full Assessment with Event Logs
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -EventLogHours 48
```
Includes 48 hours of event log analysis for actual DES/RC4 usage.

### Cross-Domain Assessment
```powershell
.\RC4_DES_Assessment.ps1 -Domain child.contoso.com -AnalyzeEventLogs
```

### With Export and Guidance
```powershell
.\RC4_DES_Assessment.ps1 -AnalyzeEventLogs -ExportResults -IncludeGuidance
```
Full assessment with JSON/CSV export and manual validation guidance.

### Testing Without Active Directory
```powershell
.\Test-RC4Script.ps1
```
Test display formatting, emojis, encryption decoding, and helper functions without requiring AD access. Perfect for validating the script works before running in production.

### Comparing Assessments Over Time
```powershell
.\Compare-Assessments.ps1 -BaselineFile old.json -CurrentFile new.json -ShowDetails
```
Compare two assessment results to track improvements, identify new issues, and validate remediation efforts.

### Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Domain` | Target domain to assess | Current domain |
| `-Server` | Specific DC to query | Any available DC |
| `-AnalyzeEventLogs` | Analyze event logs for actual usage | Not enabled |
| `-EventLogHours` | Hours of events to analyze (1-168) | 24 |
| `-ExportResults` | Export to JSON and CSV | Not enabled |
| `-IncludeGuidance` | Show manual validation guidance | Not enabled |
| `-QuickScan` | Quick scan only (explicit) | Default mode |

## Understanding the Results

### Domain Controller Assessment

```
✅ Domain Controllers are configured for AES encryption via GPO
ℹ️  3 DC(s) inherit AES settings from GPO (this is normal)
```

**What it means:** DCs are properly configured. Empty `msDS-SupportedEncryptionTypes` on DCs that inherit from GPO is expected and secure.

### Trust Assessment

```
✅ Trust 'partner.com': Uses AES by default (msDS-SupportedEncryptionTypes not set)

📘 Post-November 2022 Update:
When msDS-SupportedEncryptionTypes is not set (0 or empty) on trusts,
they default to AES encryption. No action needed for these trusts.
```

**What it means:** Trust is secure. The November 2022 update changed trusts to default to AES when the attribute is not set.

### Event Log Analysis

```
Events Analyzed: 15,432
• AES Tickets: 15,430 ✅
• RC4 Tickets: 2 ❌
• DES Tickets: 0 ✅

❌ RC4 tickets detected in active use!
Unique accounts using RC4: 2
RC4 accounts:
  - LEGACY-APP$
  - OLD-SERVER$
```

**What it means:** Despite secure DC configuration, 2 accounts are actually using RC4. These need investigation.

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

## Migration from v1.0

### Running Both Versions

v1.0 and v2.0 can coexist:
- v1.0: `RC4_AD_SCAN.ps1` (comprehensive, slow)
- v2.0: `RC4_DES_Assessment.ps1` (fast, accurate)

### Key Differences

| Feature | v1.0 | v2.0 |
|---------|------|------|
| Runtime (large forest) | 5.5+ hours | < 5 minutes |
| Computer object scan | Full enumeration | Not performed |
| Trust assessment | Pre-Nov 2022 logic | Post-Nov 2022 accurate |
| Actual usage detection | No | Yes (event logs) |
| Manual guidance | Limited | Comprehensive |
| False positives | High | Low |

### Recommended Approach

1. **Initial Assessment:** Use v2.0 for fast, accurate results
2. **Event Monitoring:** Set up continuous monitoring based on v2.0 guidance
3. **Remediation:** Address actual findings from event logs
4. **Compliance:** If required to scan all computers, use v1.0 selectively

## Troubleshooting

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
- Customer feedback and real-world testing
- Microsoft Kerberos security documentation team
- Active Directory security community

## Version History

### v2.0 (Current)
- Complete rewrite based on customer feedback
- Post-November 2022 update logic
- Event log analysis for actual usage detection
- Performance optimization for large forests
- Comprehensive manual validation guidance

### v1.0 (Legacy)
- Initial implementation
- Comprehensive computer/trust/service account scanning
- Pre-November 2022 logic
