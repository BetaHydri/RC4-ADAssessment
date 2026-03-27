# Product Context

## Why This Project Exists

Microsoft will **completely remove RC4 from the Kerberos KDC path in July 2026**.
After that date, only accounts with explicit RC4 in `msDS-SupportedEncryptionTypes`
will continue to work with RC4. Everything else gets blocked.

Organizations need to audit their AD environments, find all RC4/DES dependencies,
and remediate before the deadline. Manual assessment of large forests (thousands of
accounts, multiple domains) is impractical.

## Problems It Solves

1. **Discovery**: Finding all RC4/DES usage across a forest (config + actual ticket usage)
2. **Prioritization**: Identifying which accounts are actively using RC4 vs. just configured for it
3. **Remediation**: Providing copy-paste fix commands for every finding
4. **Progress tracking**: Comparing assessments over time to verify remediation

## User Experience Goals

- Run a single command, get a complete assessment in minutes
- Color-coded console output with clear severity indicators (OK/WARNING/CRITICAL)
- Export to JSON/CSV for reporting and tracking
- Include guidance text for teams unfamiliar with Kerberos encryption

## Key Timeline (Microsoft)

| Date | Milestone |
|------|-----------|
| Nov 2022 | OOB updates changed trust/DC Kerberos defaults |
| Jan 2026 | RC4 disablement Phase 1 (audit mode) |
| Apr 2026 | Enforcement phase (AES-only defaults) |
| Jul 2026 | RC4 fully removed from KDC path |
