# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [4.0.0] - 2026-03-30

### Changed

- Renamed module from `RC4ADCheck` to `RC4-ADAssessment` to match the repository name
- Migrated build pipeline to Sampler framework with ModuleBuilder, InvokeBuild, and Pester 5
- Restructured project layout to Sampler conventions (source/Public, source/Private)
- Added QA tests for module quality, help content, and changelog validation
- Recommended Workflow section: replaced ASCII art with Mermaid flowchart diagram and command reference table

### Fixed

- Module Commands table listed 12 private functions as user-callable commands -- now shows only the 3 exported commands
- Internal Function Mapping incorrectly marked 12 private functions as "Public" -- corrected to "Private"
- Project Structure file counts: Public 16 -> 3, Private 8 -> 20, Unit 29 -> 27
- Test count: 407 tests across 29 files -> 344 tests across 28 files
- Duplicate "Reset service account passwords" line in Recommended Workflow
- Folder casing `tests/` -> `Tests/` in Project Structure diagram
- QUICK_START.md sample output version `v2.4.0` -> `v2.9.0`

## [2.9.0] - 2026-03-27

- **AES-configured but RC4-used correlation** (major feature): New `PasswordResetNeeded` detection cross-references event log RC4 accounts (Event IDs 4768/4769) with AD account `msDS-SupportedEncryptionTypes` to identify accounts that have AES configured but are still issuing RC4 tickets because their password was never reset to generate AES keys
  - Accounts using RC4 tickets that are NOT in the RC4-only/DES-only/DES-flag lists are looked up in AD
  - If account has AES bits set (0x8/0x10) or inherits AES default (attribute not set), flagged as "Password Reset Needed"
  - New `PasswordResetNeeded` array in `EventLogs` assessment output with account name, encryption config, password age, and reason
  - Inline display during event log analysis with actionable password reset command
  - `Show-AssessmentSummary` displays PasswordResetNeeded accounts in EVENT LOG ANALYSIS SUMMARY section
  - Overall assessment generates WARNING recommendation with FGPP workaround reference
  - `Compare-Assessments.ps1` tracks `PasswordResetNeeded` count changes between assessments
  - `Assess-ADForest.ps1` aggregates PasswordResetNeeded counts in forest-wide event statistics
  - JSON export includes full PasswordResetNeeded details (no CSV change — event log data remains JSON-only)
  - New Pester test: verifies `PasswordResetNeeded` property is initialized as empty array
  - Compare-Assessments tests updated with PasswordResetNeeded test data and reduction detection test
- **Event log deserialization fix**: Fixed critical bug where `Invoke-Command` returned deserialized `EventLogRecord` objects that lost their `ToXml()` method, causing event log analysis to report 0 AES/RC4/DES tickets despite retrieving thousands of events
  - Event XML is now parsed inside the `Invoke-Command` scriptblock on the remote DC where `ToXml()` is available
  - Returns lightweight `PSCustomObject`s with pre-extracted `TargetUserName`, `TicketEncryptionType`, and `ServiceName` fields
  - RPC fallback path continues to use native `ToXml()` on local `EventLogRecord` objects
- **Guidance text file export**: When both `-ExportResults` and `-IncludeGuidance` are used together, a plain-text guidance file (`DES_RC4_Guidance_<domain>_<timestamp>.txt`) is exported alongside JSON and CSV
  - Clean plain text without Unicode decorators — suitable for sharing, tickets, or offline reference
  - Includes assessment context header (domain, date, tool version)
  - All 11 guidance sections: audit setup, SIEM queries, GPO validation, KRBTGT rotation, RC4 exception workflow, FGPP workaround, keytab impact, monitoring schedule, and reference links
  - Exported to the same `Exports/` folder as JSON/CSV files
- **Per-DC event counts in summary table**: Fixed EVENT LOG ANALYSIS SUMMARY table displaying aggregate totals on every DC row instead of per-DC counts
  - New `PerDcStats` hashtable tracks EventsAnalyzed, RC4Tickets, DESTickets, AESTickets per Domain Controller
  - Aggregate totals in summary line and JSON export remain unchanged
  - `Compare-Assessments.ps1` unaffected (uses aggregate totals only)
- **KDCSVC event reference table**: New reference table documenting Event IDs 201–209 with descriptions and recommended actions
- **gMSA/sMSA creation guide**: Step-by-step guidance for creating Group and Standalone Managed Service Accounts

## v2.8.0 (March 2026)

- **lastLogonTimestamp for all flagged accounts**: All detected accounts (Missing AES keys, RC4-only, DES-only, DES-enabled, RC4 exception, stale password, USE_DES_KEY_ONLY, RC4-only MSAs) now include `lastLogonTimestamp` to determine if accounts are still actively in use
  - New `ConvertFrom-LastLogonTimestamp` helper function (FileTime Int64 to DateTime conversion)
  - AD queries for SPN service accounts, MSAs, and DES flag accounts include `lastLogonTimestamp`
  - New fields in all account info objects: `LastLogon` (DateTime), `LastLogonDaysAgo` (int)
  - Inline display shows last logon date for each flagged account
  - New `Last Logon` column in KRBTGT & Account Encryption Summary table
  - CSV/JSON export includes `LastLogon` and `LastLogonDaysAgo` columns for all account types
  - Recommendations include last logon date per account for triage prioritization
- **Fine-Grained Password Policy (FGPP) workaround guidance**: New Section 9b in manual guidance documents the zero-disruption approach to generating AES keys by using a temporary FGPP that disables password history, allowing service account passwords to be reset with the same value
  - Step-by-step: create temporary FGPP, apply to account, reset password, replicate, remove FGPP
  - Based on real-world field experience with `sccmservice` and Cluster accounts
- **Explicit AES enforcement guidance**: New Section 9c documents that in some cases, resetting the password alone is not sufficient — you must explicitly set `msDS-SupportedEncryptionTypes` to `0x18` (AES-only) and then reset the password again to force AES key generation
  - Before/after Event ID 4768 examples showing the difference between RC4-only and AES-enabled
  - Clarifies that `Available Keys: AES-SHA1, RC4` is expected (AD always stores RC4 keys)
- **Missing AES key accounts added to summary table**: These accounts now appear in the KRBTGT & Account Encryption Summary table alongside other account types
- **AzureADKerberos key rotation guidance**: Summary table now displays key rotation reminder with `Set-AzureADKerberosServer -RotateServerKey` and link to Microsoft documentation
  - Fixed broken "Cloud Kerberos Trust deployment" link in README.md (old URL returned 404)
  - Updated to correct URLs: [Windows Hello for Business cloud Kerberos trust deployment guide](https://learn.microsoft.com/en-us/windows/security/identity-protection/hello-for-business/deploy/hybrid-cloud-kerberos-trust) and [Passwordless security key sign-in](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-passwordless-security-key-on-premises)
  - Added note that Entra Kerberos `krbtgt` keys should be rotated on the same schedule as AD DC `krbtgt` keys
- 2 new Pester tests for lastLogonTimestamp handling (with and without logon data)

## v2.7.2 (March 2026)

- **SYSVOL GPO detection fallback fix**: Fixed `Get-DomainControllerEncryption` SYSVOL fallback path failing silently when `Get-ADObject` was not available as a mockable command in test environments
  - Added `Get-ADObject` stub to Pester test harness alongside existing AD cmdlet stubs
  - Fixed Pester mock parameter type mismatch: `$Identity` bound as `ADComputer` object caused `$Identity -eq 'string'` comparisons to fail; resolved by using string interpolation (`"$Identity"`) in mock bodies
  - All 204 Pester tests now pass on machines without the ActiveDirectory module

## v2.7.1 (March 2026)

- **Linux / Kerberos keytab impact guidance**: New subsection in KRBTGT rotation procedure warning that password rotation invalidates keytab files for Linux services (Apache, Nginx, SSSD, Samba, PostgreSQL, IBM WebSphere, etc.)
  - `ktpass` (Windows) and `ktutil` (Linux) keytab regeneration commands with AES256 examples
  - Verification step: `kinit -kt /etc/krb5.keytab <principal>`
  - Troubleshooting: check `msDS-SupportedEncryptionTypes` includes `0x10` (AES256) and password was reset after setting encryption type
  - Reference links: AD Hardening Series Part 4, keytab creation guide, `ktpass` command reference, Samuraj RC4-to-AES migration guide
- **Service account remediation keytab warning**: Inline reminder in Section 6 service account update commands that Linux services using keytabs must regenerate them after encryption type changes and password resets
- **KRBTGT rotation recommendation keytab notes**: Inline keytab impact comments added to KRBTGT rotation fix commands in overall assessment recommendations

## v2.7.0 (March 2026)
- **DC discovery refactored to `Get-ADDomainController -Filter *`**: All functions now use the authoritative DC Locator (Configuration partition) instead of querying the `OU=Domain Controllers` container
  - `Get-ADDomainController -Filter *` returns only registered DCs from NTDS Settings — no false positives from non-DC objects in the OU, no false negatives from DCs moved out of the default OU
  - AzureADKerberos filtering removed from `Get-KdcRegistryAssessment`, `Get-KdcSvcEventAssessment`, `Get-AuditPolicyCheck`, `Get-EventLogEncryptionAnalysis` — no longer needed since `Get-ADDomainController` never returns the proxy object
  - AzureADKerberos detection in `Get-DomainControllerEncryption` now uses a targeted `Get-ADComputer -Identity 'AzureADKerberos'` lookup instead of filtering a full OU query
  - Per-DC encryption properties (`msDS-SupportedEncryptionTypes`, `OperatingSystem`) read via `Get-ADComputer` using `ComputerObjectDN` from the DC Locator result
  - GPO inheritance check (`Get-GPInheritance`) still uses the DC OU path (required by the cmdlet)
- **No breaking changes to JSON/CSV export format**: Compare-Assessments.ps1 works unchanged with v2.6.0 and v2.7.x exports
- Updated Pester tests to mock `Get-ADDomainController -Filter *` for DC discovery across all assessment functions

## v2.6.0 (March 2026)
- **AES-first hardening**: All default fix commands now use `0x18` (AES-only) instead of `0x1C`
  - `0x1C` (RC4 + AES) is now only recommended as a documented fallback when AES breaks an application
  - Aligns with July 2026 enforcement: only accounts with explicit RC4 in `msDS-SupportedEncryptionTypes` can still use RC4
- **RC4 exception account detection**: Accounts with explicit RC4 + AES (`0x1C` or any value with both RC4 and AES bits) are now flagged as WARNING
  - Detected across SPN service accounts (`Get-ADUser`) and gMSA/sMSA/dMSA (`Get-ADServiceAccount`)
  - New properties: `RC4ExceptionAccounts`, `TotalRC4Exception` in assessment output
  - Summary line, summary table row, recommendation with hardening commands, CSV/JSON export
  - Compare-Assessments.ps1: tracks RC4 exception count changes between assessments
- **Updated guidance**: Section 8 (RC4 Exception Workflow) restructured with AES-first approach and clear "last resort" language for RC4 exceptions
- **DefaultDomainSupportedEncTypes**: Fix commands now recommend per-account `0x1C` exceptions instead of domain-wide `0x1C` (which leaves all accounts vulnerable to CVE-2026-20833)
- 8 new Pester tests for RC4 exception detection and comparison logic

## v2.5.1 (March 2026)
- **AzureADKerberos exclusion refinement**: Explicit filtering of AzureADKerberos from DC list in KDC registry and KDCSVC event log queries
- **DES-enabled account detection**: Accounts with DES encryption bits set alongside AES are now flagged as WARNING (DES removed in Server 2025)
  - Detects DES bits on SPN user accounts (`Get-ADUser` with SPN filter) and gMSA/sMSA/dMSA (`Get-ADServiceAccount`)\n- **dMSA support**: Delegated Managed Service Accounts (Windows Server 2025, `msDS-DelegatedManagedServiceAccount`) are now correctly identified as \"dMSA\" instead of \"sMSA\"
  - Summary line, summary table row, recommendation with fix commands, CSV/JSON export, and Compare-Assessments comparison
  - 5 new Pester tests for DES-enabled detection scenarios
- **Fixed**: Explicit RC4 exception value corrected from `0x24` to `0x1C` (RC4 + AES128 + AES256) — `0x20` is compound identity/FAST armor, not AES256
- `msDS-SupportedEncryptionTypes` reference table added to README with hex/decimal values and source link
- Dead AskDS blog link replaced with live [Decrypting Kerberos Encryption Types](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/decrypting-the-selection-of-supported-kerberos-encryption-types/1628797) reference
- Version history moved to [CHANGELOG.md](CHANGELOG.md) to reduce README size

## v2.5.0 (March 2026)
- **AzureADKerberos detection**: `AzureADKerberos` (Entra Kerberos proxy) object in DC OU is now automatically detected and excluded from all DC encryption counts
- Separate informational display for AzureADKerberos in summary tables and CSV/JSON exports
- Compare-Assessments.ps1: shows AzureADKerberos presence note in DC comparison
- New Pester tests for AzureADKerberos filtering (with real DCs, alone, absent)

## v2.4.0 (March 2026)
- **CVE-2026-20833** support: KDCSVC System event scanning (events 201-209)
- `RC4DefaultDisablementPhase` value 2 (Enforcement mode) recognition
- Phased recommendation workflow: value 1 (Audit) → monitor KDCSVC events → value 2 (Enforce)
- April 2026 Enforcement phase added to timeline
- Explicit RC4 exception value `0x1C` (decimal 28 = RC4 + AES128 + AES256) for per-account exceptions
- Domain-wide `DefaultDomainSupportedEncTypes` fallback warning (leaves accounts vulnerable to CVE-2026-20833)
- Compare-Assessments.ps1: KDCSVC event comparison across assessments
- CVE-2026-20833 KB5073381 reference documentation added
- 173 Pester unit tests (12 new for KDCSVC events and Enforcement mode)

## v2.3.0 (March 2026)
- KDC registry assessment (`DefaultDomainSupportedEncTypes`, `RC4DefaultDisablementPhase`)
- Kerberos audit policy pre-check before event log analysis
- Missing AES keys detection (accounts with passwords predating DFL 2008)
- Inline remediation commands shown with every finding (no switch needed)
- July 2026 RC4 removal timeline and January 2026 update guidance
- Explicit RC4 exception workflow for user and computer accounts
- `klist purge` in all remediation steps
- Compare-Assessments.ps1: account changes, registry keys, missing AES keys
- Microsoft Kerberos-Crypto tools references

## v2.2.0 (February 2026)
- KRBTGT password age and encryption type assessment
- USE_DES_KEY_ONLY flag detection
- Service account (SPN) RC4/DES-only encryption detection
- gMSA/sMSA encryption review
- Stale password service account detection (>365 days with RC4)

## v2.1.0 (December 2025)
- WinRM-first event log queries with RPC fallback
- Full forest DC enumeration per domain
- Child domain support fixes
- Comprehensive summary tables

## v2.0.0 (October 2025)
- Complete rewrite with post-November 2022 logic
- Fast execution (< 5 minutes vs 5+ hours in v1.0)
- Event-based actual usage detection
