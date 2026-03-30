# Project Brief: RC4-ADAssessment

## Overview

**RC4-ADAssessment** is a PowerShell toolkit for assessing DES and RC4 Kerberos encryption
usage in Active Directory environments. It helps organizations prepare for Microsoft's
**July 2026 RC4 removal deadline** by discovering all RC4/DES usage across an AD forest.

## Core Requirements

1. **DC Encryption Assessment** — Scan all Domain Controllers for `msDS-SupportedEncryptionTypes` and GPO Kerberos policy
2. **Trust Assessment** — Evaluate trust encryption with post-Nov 2022 logic (AES default when attribute is not set)
3. **KDC Registry Check** — Read `DefaultDomainSupportedEncTypes` and `RC4DefaultDisablementPhase` from all DCs
4. **KDCSVC Event Scan** — Query System log events 201–209 for RC4 risks (CVE-2026-20833)
5. **Audit Policy Verification** — Check if Kerberos auditing (4768/4769) is enabled
6. **Event Log Analysis** — Query events 4768/4769 from all DCs for actual RC4/DES ticket usage
7. **AES/RC4 Correlation** — Detect accounts needing password reset (have AES configured but still use RC4)
8. **KRBTGT Assessment** — Password age, encryption types, rotation guidance
9. **Service Account Scan** — SPN accounts, gMSA/sMSA/dMSA with RC4/DES-only encryption
10. **Inline Fix Commands** — Every finding includes copy-paste PowerShell remediation
11. **Forest-Wide Scanning** — Assess all domains with parallel processing (PS 7+)
12. **Assessment Comparison** — Track remediation progress between two exports

## Target Users

- Active Directory administrators
- Security engineers preparing for RC4 deprecation
- Compliance teams needing audit evidence

## Technical Constraints

- PowerShell 5.1+ (7+ for parallel forest assessment)
- Requires `ActiveDirectory` and `GroupPolicy` modules
- Domain Admin or equivalent permissions
- WinRM/RPC connectivity to DCs for event log and registry queries

## Success Metrics

- All RC4/DES usage discovered across the forest in < 5 minutes
- Actionable remediation commands for every finding
- Progress tracking between assessment runs
