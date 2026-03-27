# Progress

## What Works

- **v2.9.0** (current) — Full assessment toolkit with 12+ check categories
- **204 Pester 5 tests** passing across 4 test files
- **AES/RC4 correlation** — Password reset detection for accounts with AES config but RC4 usage
- **Forest-wide scanning** — Parallel domain assessment with PS 7+
- **Assessment comparison** — JSON-based progress tracking
- **Inline remediation** — Copy-paste fix commands for every finding
- **Event log analysis** — Real-world RC4/DES ticket usage detection
- **KDCSVC events** — CVE-2026-20833 assessment
- **Guidance export** — Plain text reference manual

## What's In Progress

- **Sampler migration** — Converting from standalone scripts to Sampler module structure
  - Extract functions into individual files (source/Public/, source/Private/)
  - Create module manifest and build infrastructure
  - Set up GitVersion, PSScriptAnalyzer, CI/CD pipeline
  - Adapt existing tests to module-based imports

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

- Version string duplicated across multiple files (script metadata, README, CHANGELOG, tests)
- No automated build/release pipeline
- Tests use regex function extraction instead of module imports
- No PSScriptAnalyzer enforcement
- No code coverage tracking
