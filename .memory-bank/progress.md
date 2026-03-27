# Progress

## What Works

- **v3.0.0-preview** (Sampler module) — Full assessment toolkit with 16 public + 8 private functions
- **407 Pester 5 tests** (383 passed, 24 skipped) across 29 test files
- **Sampler build pipeline** — `build.ps1 -Tasks test` succeeds (9 tasks, 0 errors)
- **AES/RC4 correlation** — Password reset detection for accounts with AES config but RC4 usage
- **Forest-wide scanning** — Parallel domain assessment with PS 7+
- **Assessment comparison** — JSON-based progress tracking
- **Inline remediation** — Copy-paste fix commands for every finding
- **Event log analysis** — Real-world RC4/DES ticket usage detection with WinRM/RPC fallback
- **KDCSVC events** — CVE-2026-20833 assessment
- **Guidance export** — Plain text reference manual

## What's Left

- Update README.md and QUICK_START.md for module-based usage (still reference standalone scripts)
- Add PSScriptAnalyzer custom rules
- Set up Azure Pipelines CI/CD
- Consider code coverage targets
- PR review and merge to main

## Version History

| Version | Date | Key Feature |
|---------|------|-------------|
| v2.9.0 | Mar 2026 | AES/RC4 password-reset-needed correlation |
| v2.8.x | Mar 2026 | lastLogonTimestamp, FGPP guidance, event deserialization fix |
| v2.7.x | Mar 2026 | DC discovery refactored, SYSVOL GPO fallback, keytab guidance |
| v2.6.0 | Mar 2026 | AES-first hardening, RC4 exception detection |
| v2.5.x | Mar 2026 | AzureADKerberos exclusion, DES detection |
| v2.4.0 | Mar 2026 | KDCSVC event scan, KDC registry assessment |
| v2.3.0 | Mar 2026 | Comparison tool, inline remediation, timeline |
| v1.0 | Oct 2025 | Initial release (archived) |

## Known Issues

- README.md and QUICK_START.md still reference standalone scripts (pre-migration)
- 24 QA tests skipped (expected — module not published to gallery yet)
- No code coverage tracking enabled yet
- No CI/CD pipeline configured yet
