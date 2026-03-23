# Changelog

All notable changes to this project will be documented in this file.

## v2.5.1 (March 2026) — Current
- **AzureADKerberos exclusion refinement**: Explicit filtering of AzureADKerberos from DC list in KDC registry and KDCSVC event log queries

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
- Explicit RC4 exception value changed from `0x1C` to `0x24` (RC4 + AES256 session keys) per Microsoft guidance
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
