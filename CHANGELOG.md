# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- GPO-vs-AD etype drift detection in `Get-KdcRegistryAssessment` — reads
  `SupportedEncryptionTypes` from the GPO Policies registry path on each DC and
  compares against the DC's `msDS-SupportedEncryptionTypes` AD attribute to detect
  pending Kerberos service restarts or manual overrides (#31)
- Etype drift tracking in `Invoke-RC4AssessmentComparison` — shows drift DC count
  changes between baseline and current assessments (#31)

### Fixed

- `Get-KdcRegistryAssessment` falls back to local registry read when
  `Invoke-Command` fails on the DC the tool is running on (loopback WinRM
  cold-start issue)

## [4.15.0] - 2026-04-28

### Changed

- `DefaultDomainSupportedEncTypes` with RC4 now reported as WARNING instead of
  OK/INFO — DDSET with RC4 overrides enforcement for ALL accounts without explicit
  `msDS-SupportedEncryptionTypes`, not just per-account exceptions (#34)
- Clarified that per-account RC4 exceptions (`0x1C`) do NOT require DDSET to
  include RC4

### Fixed

- FAQ (DE): `RC4DefaultDisablementPhase` table updated — added "Not set" row,
  corrected Phase 0/1 descriptions, fixed "Kein Neustart" to
  "KDC-Neustart erforderlich" (#26, #28, #29)
- FAQ (DE/EN): Added KB5073381 note that explicit DDSET overrides implicit
  enforcement default (#32)
- Guidance text: `RC4DefaultDisablementPhase` registry path corrected from
  `Services\Kdc` to Policies path (#23)
- Guidance text: Phase 0/1 descriptions updated for post-April 2026
  semantics (#28, #29)

## [4.14.0] - 2026-04-28

### Added

- Context-aware `Get-EncryptionTypeString` with `-Context` parameter (`msds`,
  `ddset`, `gpo`) — same bitmask is now decoded differently per context (#30)
- AES256-HMAC-SK (bit `0x20`) decoding in `Get-EncryptionTypeString` (#25)
- Feature flag decoding (bits 16-19: FAST, Compound-Identity, Claims,
  Resource-SID-Compression) for `msds` context
- Enforcement block detection (`TicketEncryptionType = 0xFFFFFFFF`) in
  `Get-TicketEncryptionType` and `Get-EventLogEncryptionAnalysis` with per-DC
  counter and affected-account tracking (#27)

### Changed

- `Get-KdcRegistryAssessment` reads `RC4DefaultDisablementPhase` from the correct
  Policies registry path instead of `Services\Kdc` (#23)
- `Get-AccountEncryptionAssessment` RODC group lookup uses well-known RID 521
  instead of English display name — works on non-English DCs (#24)
- `RC4DefaultDisablementPhase` assessment messages updated for post-April 2026
  semantics: `not set` = implicit enforcement, Phase 0/1 = rollback states (#28)
- Phase 1 description clarifies per-request KDCSVC event logging (#29)
- GPO encryption type callers pass `-Context gpo`, DDSET callers pass
  `-Context ddset` for accurate bitmask decoding

### Fixed

- `Get-EncryptionTypeString` no longer labels bit 31 as "Future" universally —
  "Future encryption types" at the GPO level is bits 5-30 (`0x7FFFFFE0`),
  not bit 31 (#30)
- README/FAQ/QUICK_START: "No reboot required" corrected to "KDC restart
  required" for `RC4DefaultDisablementPhase` (#26)
- README/FAQ: Phase value table updated — `not set` is now enforcement (not
  same as 0) after April 2026 CU (#28)
- QUICK_START: Registry path in remediation snippet corrected to Policies path (#23)

## [4.13.0] - 2026-04-17

### Changed

- Missing AES Keys Path B now uses a dynamic AES threshold date derived from the
  "Read-only Domain Controllers" group creation date (proxy for DFL 2008 upgrade)
  instead of a hardcoded 5-year password age heuristic
- Falls back to Windows Server 2008 GA date (2008-02-27) when the RODC group is absent
- Displays the detected AES threshold date as an INFO finding during assessment

### Fixed

- PS 5.1 parse error caused by em-dash (U+2014) in string literal corrupting to
  `a]"` after ModuleBuilder BOM stripping -- replaced with ASCII `--`
- Missing `Set-ADServiceAccount` caveat on the "Missing AES Keys" remediation command
- Added `Get-ADGroup` mock to `RC4-ADAssessment.Tests.ps1` Missing AES Keys tests
  for correct dynamic threshold resolution in CI

## [4.12.0] - 2026-04-16

### Added

- RODC (Read-Only Domain Controller) assessment support in `Get-DomainControllerEncryption`:
  tracks `RODCCount` and `IsReadOnly` per DC, displays `[RODC]` label in console output
- RODC KRBTGT account (`krbtgt_*`) discovery and assessment in
  `Get-AccountEncryptionAssessment`: checks password age (CRITICAL >365d, WARNING >180d)
  and detects RC4-only encryption
- RODC KRBTGT summary table in `Show-AssessmentSummary` with color-coded status and
  password rotation guidance
- Null-safety for environments without RODCs — all RODC counters default to zero
- 9 new Pester unit tests for RODC DC detection, RODC KRBTGT discovery, password age,
  encryption type checks, and no-RODC scenarios (524 total tests, 67.69% coverage)

## [4.11.0] - 2026-04-16

### Fixed

- Banner version in all three public commands (`Invoke-RC4Assessment`,
  `Invoke-RC4ForestAssessment`, `Invoke-RC4AssessmentComparison`) now dynamically
  reads the module version from the manifest at import time, so the displayed
  version always matches the installed release
- `Invoke-RC4ForestAssessment` and `Invoke-RC4AssessmentComparison` banners were
  missing the version number entirely
- Removed stale `CHANGELOG-Surface_Laptop7.md` duplicate file

## [4.10.0] - 2026-04-15

### Fixed

- Remediation commands now note that gMSA/sMSA/dMSA require `Set-ADServiceAccount` instead
  of `Set-ADUser` (which cannot find Managed Service Account objects). Added to all inline
  fix commands in `Invoke-RC4Assessment`, `-IncludeGuidance` output (`Show-ManualValidationGuidance`),
  and exported guidance text (`Get-GuidancePlainText`). Also clarifies that MSA passwords are
  managed by AD — no manual `Set-ADAccountPassword` reset is needed; AES keys are generated
  at the next automatic password rotation. Computer accounts already correctly use `Set-ADComputer`.

### Changed

- "RC4 tickets detected in event logs" downgraded from CRITICAL to WARNING — RC4 tickets may
  originate from intentional `0x1C` exception accounts that will continue functioning after
  July 2026 enforcement
- "Missing AES keys" upgraded from WARNING to CRITICAL — accounts with no AES keys (explicit
  non-AES encryption or very old passwords predating AES key generation) will break after
  enforcement phase

## [4.9.0] - 2026-04-15

### Added

- Pester unit tests for `Invoke-RC4ForestAssessment` covering forest discovery,
  sequential domain assessment, parameter forwarding, DC hostname extraction,
  status aggregation, export logic, and error handling paths

### Changed

- Azure Pipelines now publishes JaCoCo code coverage as a visual report tab
- Pipeline ensures `testResults/` directory exists before publishing artifacts

## [4.8.0] - 2026-04-15

### Fixed

- KDCSVC event query now matches both provider names (`KDCSVC` and
  `Microsoft-Windows-Kerberos-Key-Distribution-Center`). Some Windows Server versions log
  KDC events 201-209 under the latter provider, causing the assessment to report zero events
  even when events exist.

### Changed

- Azure Pipelines now publishes JaCoCo code coverage as a visual report tab (not just
  a downloadable artifact)

## [4.7.0] - 2026-04-13

### Fixed

- Export filenames in multi-forest scans now contain the correct assessed domain name instead
  of the caller's (logged-in user's) domain. `Invoke-DomainAssessment` omitted `-Domain` when
  passing `-Server`, causing `Invoke-RC4Assessment` to fall back to `(Get-ADDomain).DNSRoot`.
- `Invoke-RC4Assessment` now resolves the domain name from the target server when only `-Server`
  is provided (defense-in-depth)

### Changed

- Forest summary exports (`Forest_Assessment_*.json|csv`) now go to the `Exports/` subfolder,
  consistent with per-domain exports

## [4.6.0] - 2026-04-11

### Added

- Human-readable direction labels in trust assessment details (e.g. `3 (Bidirectional)`,
  `2 (Outbound)`) replacing raw integer values
- `TrustDirection` mapping handles both integer and string enum values from `Get-ADTrust`
- 2 new Pester tests for direction label output (total: 494 tests)

## [4.5.0] - 2026-04-07

### Fixed

- `RC4DefaultDisablementPhase = 1` recommendation text incorrectly stated it "enables KDCSVC
  audit events". KDCSVC events are logged by the January 2026+ security update regardless of
  the phase value. Phase 1 is an administrative checkpoint for change management, not a
  technical gate for event logging. Only phase 2 changes KDC behaviour (enforcement).
- Updated recommendation text in `Invoke-RC4Assessment`, `Get-KdcRegistryAssessment`, and
  sample outputs in `QUICK_START.md` and `README.md`

## [4.4.0] - 2026-04-07

### Fixed

- KDCSVC note incorrectly stated events require `RC4DefaultDisablementPhase >= 1` to be logged.
  KDCSVC events are generated by the January 2026+ security update regardless of the phase setting.
  The phase controls enforcement, not logging.

### Changed

- Missing AES Keys detection rewritten with two-path approach:
  - **Path A**: Accounts with `msDS-SupportedEncryptionTypes` explicitly set to a non-zero value
    without AES bits (e.g., `0x4` = RC4-only, `0x3` = DES-only). Detected regardless of password age.
  - **Path B**: Accounts with attribute not set (null/0) AND password older than 5 years
    (may predate DFL 2008 upgrade). Original logic, now scoped correctly.
- Standard scan now detects RC4-only and DES-only accounts without `-DeepScan`
- `-DeepScan` now focuses on RC4-exception/DES-enabled users without SPNs and computer accounts
- Summary label changed from "Accounts Missing AES Keys (pwd >5yr)" to "Accounts Missing AES Keys"

### Added

- 4 new unit tests for Path A, Path B, and negative case (AES bits present) (total: 492 tests)
- `-IncludeGuidance` section 9 updated with Path A/B detection explanation and separate queries
- "Standard Scan vs DeepScan" comparison table in README
- Real-world example in README showing Path A detection without `-DeepScan`

## [4.3.0] - 2026-04-07

### Fixed

- Event log analysis incorrectly reported DCs as "Failed" (red) when no 4768/4769 events
  existed in the time window. `Get-WinEvent` throws "No events were found that match the
  specified selection criteria" which was caught as a query failure instead of an empty result.
  DCs now correctly appear as "Success" with zero event counts.
- Empty event array check now uses `@($events).Count -eq 0` for PowerShell 5.1/7 consistency
- Fixed `PSUseBOMForUnicodeEncodedFile` PSScriptAnalyzer warning on `Get-EventLogEncryptionAnalysis.ps1`

### Added

- 2 new unit tests for "no events found" handling (total: 488 tests)

## [4.2.0] - 2026-04-07

### Added

- Track `SessionKeyEncryptionType` alongside `TicketEncryptionType` in event log analysis,
  following Microsoft's `Get-KerbEncryptionUsage.ps1` pattern ([Kerberos-Crypto](https://github.com/microsoft/Kerberos-Crypto))
- New counters: `SessionKeyRC4`, `SessionKeyDES`, `SessionKeyAES`, `RC4SessionKeyAccounts`
- `RC4 SessKey` column in per-DC summary table and forest summary table
- `RC4 Session Keys` comparison line in `Invoke-RC4AssessmentComparison` (backward-compatible
  with older JSON exports)
- Detect old event format (pre-January 2025 cumulative update) and show informational message
  instead of misleading zeros
- 6 new unit tests for session key tracking (total: 486 tests)

### Changed

- GPO recommendation text now includes **Future encryption types** alongside AES128_HMAC_SHA1 and AES256_HMAC_SHA1, per CIS Benchmark 2.3.11.4
- `Get-EncryptionTypeString` recognises the `0x80000000` (Future encryption types) bit
- Updated guidance in `Get-GuidancePlainText` and `Show-ManualValidationGuidance` GPO Validation sections
- Updated DeepScan inline info message to reference Future encryption types

## [4.1.2] - 2026-03-31

### Fixed

- `Invoke-RC4ForestAssessment` crashed with `Split-Path: Cannot bind argument to
  parameter 'Path' because it is null` and `RC4_DES_Assessment.ps1 not found` when
  running as a module function because legacy standalone-script path validation
  used `$MyInvocation.MyCommand.Path` (null for module functions) and referenced
  an undefined `$assessmentScript` variable
- Sequential domain processing in `Invoke-RC4ForestAssessment` invoked
  `& $ScriptDir @params` instead of calling `Invoke-RC4Assessment` directly
  (the parallel code path was already correct)

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
