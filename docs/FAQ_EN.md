---
title: "RC4-ADAssessment — Frequently Asked Questions"
subtitle: "DES/RC4 Kerberos Encryption Assessment Tool"
author: "Jan Tiedemann"
date: "April 2026"
---

# RC4-ADAssessment — FAQ

## General

**Q: What does this tool do?**

It assesses DES and RC4 Kerberos encryption usage across your Active Directory
forest. It scans Domain Controllers, trusts, KRBTGT, service accounts
(SPN/gMSA/sMSA/dMSA), KDC registry keys, KDCSVC events (CVE-2026-20833), and
Security event logs (4768/4769) for actual RC4/DES ticket usage. Every finding
includes copy-paste remediation commands.

**Q: Why do we need this tool?**

Microsoft will completely remove RC4 from the Kerberos KDC path in **July 2026**.
After that date, only accounts with *explicit* RC4 in
`msDS-SupportedEncryptionTypes` will work with RC4. Everything else gets blocked.
This tool helps you discover all RC4/DES usage, get inline fix commands, track
remediation progress, and prepare for the deadline.

**Q: Who is this tool for?**

Active Directory administrators, security teams, and infrastructure engineers who
need to prepare their AD environments for the RC4 removal deadline.

## Timeline & Milestones

**Q: What are the key milestones for the RC4 removal?**

| Date | Milestone |
|------|-----------|
| Nov 2022 | Trusts and computers default to AES when attribute is unset |
| Jan 2026 | `RC4DefaultDisablementPhase` registry key added (CVE-2026-20833) |
| Apr 2026 | Enforcement phase — `DefaultDomainSupportedEncTypes` defaults to AES-only |
| Jul 2026 | Full enforcement — RC4 registry override removed |

**Q: What happens after July 2026 if we don't act?**

- Accounts relying on default/legacy RC4 fallback will be **blocked**.
- Accounts without `msDS-SupportedEncryptionTypes` set will use AES (safe).
- Accounts with AES in `msDS-SupportedEncryptionTypes` will use AES (safe).
- Accounts with explicit RC4 (`0x1C`) will still work as exceptions.

## Requirements

**Q: What permissions are required?**

Domain Admin or equivalent. Event Log Readers group membership is needed for event
log analysis. Network access via WinRM (port 5985) or RPC (port 135) to Domain
Controllers is required.

**Q: What PowerShell version is needed?**

PowerShell 5.1 or higher. PowerShell 7+ is required for parallel forest-wide
scanning with `Invoke-RC4ForestAssessment -Parallel`.

**Q: What modules are prerequisites?**

The `ActiveDirectory` and `GroupPolicy` modules (RSAT tools). Install them with:

```
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
```

## Scanning & Usage

**Q: How long does a scan take?**

- Quick scan (config only): ~30 seconds
- Deep scan (all users/computers): ~1–2 minutes
- Full scan with event logs: ~3–5 minutes

**Q: What is the difference between a quick scan and a deep scan?**

A quick scan checks Domain Controllers, trusts, KRBTGT, and SPN-bearing service
accounts. A deep scan (`-DeepScan`) additionally scans all enabled user accounts
and all computer accounts (excluding DCs) for RC4/DES configurations. Deep scan
does NOT include event log analysis — combine with `-AnalyzeEventLogs` for full
coverage.

**Q: Can it scan an entire multi-domain forest?**

Yes. `Invoke-RC4ForestAssessment` scans all domains in the forest. Optional
parallel processing with `-Parallel -MaxParallelDomains 5` is available on
PowerShell 7+.

**Q: What are the three main commands?**

| Command | Purpose |
|---------|---------|
| `Invoke-RC4Assessment` | Main assessment for a single domain |
| `Invoke-RC4ForestAssessment` | Forest-wide assessment across all domains |
| `Invoke-RC4AssessmentComparison` | Compare two JSON exports to track progress |

**Q: Can we track remediation progress over time?**

Yes. Export results to JSON with `-ExportResults`, then compare two runs:

```
Invoke-RC4AssessmentComparison -BaselineFile before.json -CurrentFile after.json -ShowDetails
```

It compares DC encryption, trusts, accounts, KDC registry, KDCSVC events, and
event log ticket counts.

**Q: What export formats are available?**

JSON (full data) and CSV (summary table), saved to the `.\Exports\` folder. With
`-IncludeGuidance`, an additional `.txt` guidance file is generated.

## Technical Details

**Q: Does it cover CVE-2026-20833?**

Yes, fully. The tool scans KDCSVC System log events 201–209, checks
`RC4DefaultDisablementPhase` registry values on all DCs, and maps all KB article
requirements including Audit mode (value 1) and Enforcement mode (value 2).

**Q: I see no KDCSVC events 201–209 on my DCs. Does that mean RC4 is gone?**

**No.** This is a common misconception. KDCSVC events 201–209 are a
**CVE-specific warning mechanism**, not a general-purpose RC4 scanner. Microsoft
states in KB5073381: *"Audit events related to this change are only generated
when Active Directory is unable to issue AES-SHA1 service tickets or session
keys. The absence of audit events does not guarantee that all non-Windows
devices will successfully accept Kerberos authentication."*

Many legitimate RC4 scenarios produce **no KDCSVC events at all**, including:

- Accounts without `msDS-SupportedEncryptionTypes` that implicitly use RC4
- RC4 session keys visible in Security events 4768/4769 but not triggering KDC
  fallback logic
- Legacy service accounts with formally valid but cryptographically weak configs

This is why RC4-ADAssessment correlates multiple data sources (AD attributes,
KDC registry, KDCSVC events, *and* Security event logs 4768/4769) rather than
relying on any single signal. No KDCSVC events does not equal no RC4.

References:

- [KB5073381 — CVE-2026-20833 deployment guidance](https://support.microsoft.com/topic/1ebcda33-720a-4da8-93c1-b0496e1910dc)
- [Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

**Q: What about the AzureADKerberos object in the DC OU?**

It is automatically detected and excluded from DC counts. The AzureADKerberos
object is a read-only proxy for Entra ID Cloud Kerberos Trust — it is not a real
Domain Controller. Do not modify its encryption settings manually.

**Q: Does the KDC need RC4 enabled to issue RC4 tickets for excepted accounts?**

**No.** The RC4 code path remains in the KDC after July 2026. Setting
`msDS-SupportedEncryptionTypes = 0x1C` on a service account is sufficient — the
KDC issues RC4 tickets for that specific account only, while all other accounts
remain AES-only. No domain-wide registry change is needed.

**Q: What is the recommended encryption type value?**

- **24 (0x18)** = AES128 + AES256 — **Recommended (AES-only)**
- **28 (0x1C)** = RC4 + AES128 + AES256 — Last resort for legacy applications

**Q: How does "Missing AES Keys" detection work?**

Accounts are flagged when `msDS-SupportedEncryptionTypes` is not set **and**
`PasswordLastSet` is older than 5 years. These accounts may never have had AES
keys generated (because AES keys are only created when a password is set while the
Domain Functional Level is 2008 or higher). Fix: reset the password.

**Q: What does the AES/RC4 correlation detect?**

Accounts that have AES *configured* in AD but are still obtaining RC4 tickets
(visible in event logs). This means the password was never reset after AES was
configured, so no AES keys exist. Fix: reset the password and purge tickets.

**Q: Does it provide remediation commands?**

Yes. Every finding includes inline, copy-paste-ready PowerShell remediation
commands. The `-IncludeGuidance` switch adds a full reference manual covering
audit setup, SIEM queries, KRBTGT rotation, and the July 2026 timeline.

**Q: Do I need to set encryption types on all computer accounts?**

**No.** Post-November 2022, RC4 fallback for computers only occurs if the
client's attribute is non-zero AND the DC lacks AES. If your DCs have AES
configured via GPO, no action is needed on normal computer accounts.

## Impact & Side Effects

**Q: What about Linux services using Kerberos keytabs?**

Password resets invalidate existing keytab files. Linux services (Apache, Nginx,
SSSD, Samba, PostgreSQL, etc.) will need keytab regeneration via `ktpass`
(Windows) or `ktutil` (Linux). The `-IncludeGuidance` output includes
step-by-step keytab regeneration commands.

**Q: What is the recommended workflow?**

1. **Discovery** — Full scan with event logs and export
2. **Remediate** — Fix high-risk items using inline fix commands
3. **Validate** — Compare baseline and current assessments
4. **Deep Sweep** — Scan all users and computer accounts
5. **Final Remediate** — Password resets for remaining accounts
6. **Final Validate** — Confirm everything is clean — ready for July 2026

## Installation

**Q: How do I install it?**

```
Install-Module -Name RC4-ADAssessment
Import-Module RC4-ADAssessment
```

**Q: Does the tool make any changes to Active Directory?**

No. The tool is strictly **read-only**. It queries AD attributes, registry keys,
and event logs but never modifies anything. The remediation commands are displayed
for the administrator to review and execute manually.
