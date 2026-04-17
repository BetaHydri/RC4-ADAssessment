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

**Q: What is the difference between Kerberos tickets and session keys?**

Kerberos uses two distinct cryptographic layers, and each can independently use
RC4 or AES:

- **Tickets (TGT and TGS):** The TGT (Ticket Granting Ticket) is issued during
  initial authentication (AS-REQ) and encrypted with the KRBTGT account's key.
  The TGS (service ticket) is issued when accessing a service (TGS-REQ) and
  encrypted with the target service account's key. The ticket encryption type is
  determined by the target account's `msDS-SupportedEncryptionTypes` and the
  KDC's configuration. This is what the `TicketEncryptionType` field in Security
  events 4768/4769 shows.
- **Session keys:** A temporary symmetric key generated by the KDC and placed
  inside the ticket. The session key encrypts the ongoing communication between
  client and service (or client and KDC). Its encryption type is negotiated
  separately and can differ from the ticket encryption type.

**Why this matters for RC4 assessment:** A service ticket can be AES-encrypted
while the session key inside it uses RC4 — or vice versa. KDCSVC events 201–209
fire only when the KDC **cannot issue AES** for either tickets or session keys
based on the account's configuration (KB5073381: *"only generated when Active
Directory is unable to issue AES-SHA1 service tickets or session keys"*).
However, when AES **is** configured but RC4 is still **actually negotiated** —
for example because the client requests RC4, or because the account password was
never reset to generate AES keys — **no KDCSVC event is produced**. These
silent RC4 usages are only visible in the `TicketEncryptionType` and
`SessionEncryptionType` fields of Security events 4768/4769, which is why
RC4-ADAssessment includes event log correlation as a critical detection layer.
Microsoft's own `Get-KerbEncryptionUsage.ps1` script
([Kerberos-Crypto](https://github.com/microsoft/Kerberos-Crypto)) tracks
`Ticket` and `SessionKey` encryption types separately for the same reason.

References:

- [MS-KILE — Kerberos Protocol Extensions](https://learn.microsoft.com/openspecs/windows_protocols/ms-kile/2a32282e-6ab7-4f56-b532-870c74e1c653)
- [KB5073381 — CVE-2026-20833 deployment guidance](https://support.microsoft.com/topic/1ebcda33-720a-4da8-93c1-b0496e1910dc)
- [Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

**Q: In Event 4769, why does the Account section show `0x0` while the Service
section shows `0x1C`?**

This is a common source of confusion. Event 4769 (TGS Service Ticket Request)
has three sections that show different perspectives of the same ticket request:

| Section | What it shows | Example |
|---------|---------------|---------|
| **Account Information** | The raw `msDS-SupportedEncryptionTypes` AD attribute on the *requesting* account | `0x0` (not set) |
| **Service Information** | The *effective/computed* encryption types for the *target service* | `0x1C` (RC4 + AES128 + AES256) |
| **Domain Controller Information** | The KDC that processed the request | `0x0` (also not set on the DC object) |

The Account section reads the attribute value **directly from AD** — if
`msDS-SupportedEncryptionTypes` is not configured, it shows `0x0`. The Service
section shows the **effective** encryption types the KDC computed by looking at
which cryptographic keys actually exist in the AD database for that account.
Since DCs at 2008+ DFL automatically generate AES128 and AES256 keys (alongside
the RC4/NT hash), the KDC knows all three key types are available — hence `0x1C`.

**Why this matters for RC4 hardening:**

With `msDS-SupportedEncryptionTypes = 0x0`, the KDC falls back to
`DefaultDomainSupportedEncTypes` (the domain-wide default). Before July 2026,
this default **includes RC4**, meaning RC4 tickets can and will be issued if a
client requests them. After the July 2026 enforcement, the default changes to
`0x18` (AES-only), so accounts with `0x0` will automatically stop receiving RC4
tickets — no manual configuration needed.

However, if you **explicitly** set `msDS-SupportedEncryptionTypes = 0x1C` on an
account, you override the new default and **keep RC4 alive** for that account
even after July 2026. This is useful as a transitional step or last-resort
exception, but should not be left permanently.

**Example — Event 4769 on a DC requesting a ticket to itself:**

```
Account Information:
    Account Name:                    F1DC1$@FOREST1.NET
    MSDS-SupportedEncryptionTypes:   0x0 (N/A)        ← not set in AD
    Available Keys:                  N/A

Service Information:
    Service Name:                    F1DC1$
    MSDS-SupportedEncryptionTypes:   0x1C (RC4, AES128-SHA96, AES256-SHA96)
    Available Keys:                  RC4, AES128-SHA96, AES256-SHA96

Additional Information:
    Ticket Encryption Type:          0x12             ← AES256 ✓
    Session Encryption Type:         0x12             ← AES256 ✓
    Failure Code:                    0x0              ← Success
```

Even though the account attribute is `0x0` and the client advertised RC4
variants alongside AES, the KDC chose **AES256 for both ticket and session
key** — it picks the strongest available algorithm. This DC is clean. After
July 2026 with `0x0`, the default changes to `0x18` (AES-only) and this behavior
stays the same — AES256 would still be selected, with RC4 no longer even being
an option.

**Q: What about the AzureADKerberos object in the DC OU?**

It is automatically detected and excluded from DC counts. The AzureADKerberos
object is a read-only proxy for Entra ID Cloud Kerberos Trust — it is not a real
Domain Controller. Do not modify its encryption settings manually.

**Q: Does the KDC need RC4 enabled to issue RC4 tickets for excepted accounts?**

**No.** The RC4 code path remains in the KDC after July 2026. Setting
`msDS-SupportedEncryptionTypes = 0x1C` on a service account is sufficient — the
KDC issues RC4 tickets for that specific account only, while all other accounts
remain AES-only. No change to the `DefaultDomainSupportedEncTypes` registry key
(KDC fallback) is needed. Note: this is separate from the GPO "Network security:
Configure encryption types allowed for Kerberos", which writes
`msDS-SupportedEncryptionTypes` to computer objects in AD.

**Q: What is the recommended encryption type value?**

- **`0x18` (24)** = AES128 + AES256 — **Recommended (AES-only)**
- **`0x1C` (28)** = RC4 + AES128 + AES256 — Last resort for legacy applications
- **`0x3C` (60)** = RC4 + AES128 + AES256 + AES256-SK — Historical recommended
  (replace with `0x18`)
- **`0x80000018` (2147483672)** = AES128 + AES256 + Future — CIS Benchmark GPO value

**Q: What do the encryption type codes in event logs mean (4768/4769)?**

These are the `TicketEncryptionType` and `SessionKeyEncryptionType` values from
Security events — they show the single algorithm used for a specific ticket or
session key (unlike the bitmask values above which are account attribute
combinations):

| Hex | Algorithm | Status |
|-----|-----------|--------|
| `0x1` | DES-CBC-CRC | Insecure — disabled since Win 7 / Server 2008 R2 |
| `0x3` | DES-CBC-MD5 | Insecure — disabled since Win 7 / Server 2008 R2 |
| `0x11` | AES128-CTS-HMAC-SHA1-96 | Secure |
| `0x12` | AES256-CTS-HMAC-SHA1-96 | **Recommended** — strongest standard type |
| `0x17` | RC4-HMAC | Weak — blocked after July 2026 without exception |
| `0x18` | RC4-HMAC-EXP | Insecure — export-grade RC4 |

`SessionKeyEncryptionType` is only available on DCs with the January 2025+
cumulative update (extended event format). Older DCs only provide
`TicketEncryptionType`.

**Q: What are the `RC4DefaultDisablementPhase` registry values?**

The registry key is located at:

```
HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters
```

| Value | Mode | Effect |
|:-----:|------|--------|
| 0 | Disabled | No audit, no enforcement |
| 1 | Audit | KDCSVC events 201–209 logged, RC4 still works |
| 2 | Enforcement | `DefaultDomainSupportedEncTypes` defaults to `0x18`, RC4 blocked |

No reboot required. Set to `1` before April 2026 to enable monitoring.

**Q: What changes after the April 2026 patch?**

The April patch internally changes `DefaultDomainSupportedEncTypes` to `0x18`
(AES-only). Accounts without `msDS-SupportedEncryptionTypes` set will no longer
get RC4 tickets. Accounts with explicit `0x1C` (RC4+AES) continue to work. You
can still roll back to `RC4DefaultDisablementPhase = 1` (Audit) until July 2026.

**Q: How should I prepare Production vs. Test/QA environments?**

- **Production (before April 2026):** Set `RC4DefaultDisablementPhase = 1` on
  all DCs — audit only, RC4 continues to work, KDCSVC events are logged
- **Test/QA (enforce now):** Set `RC4DefaultDisablementPhase = 2` on all DCs —
  RC4 blocked for accounts without explicit `0x1C` exception

**Q: Should I set `DefaultDomainSupportedEncTypes` to `0x1C` domain-wide?**

**No — never.** That enables RC4 for *all* accounts without explicit encryption
types and makes the entire domain vulnerable to CVE-2026-20833. Use per-account
`msDS-SupportedEncryptionTypes = 0x1C` exceptions only for specific legacy
services that absolutely need RC4.

**Q: What does the GPO "Configure encryption types allowed for Kerberos" do?**

It configures which encryption types a computer offers and accepts. Enable
AES128 + AES256 + Future encryption types (= `0x80000018`, CIS Benchmark). This
GPO writes `msDS-SupportedEncryptionTypes` to computer objects in AD. It is
separate from `DefaultDomainSupportedEncTypes` (KDC registry fallback for
accounts without the attribute).

**Q: How does "Missing AES Keys" detection work?**

Accounts are flagged when `msDS-SupportedEncryptionTypes` is not set **and**
`PasswordLastSet` predates the domain's AES threshold (the date when DFL was
raised to 2008, detected via the "Read-only Domain Controllers" group creation
date). These accounts may never have had AES keys generated (because AES keys
are only created when a password is set while the Domain Functional Level is
2008 or higher). Fix: reset the password.

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
