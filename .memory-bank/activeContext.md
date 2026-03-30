# Active Context

## Current Focus

Sampler migration complete. All tests pass. Branch `feature/sampler-migration` ready for PR review.

## Critical Rule

**NEVER run `build.ps1` or `Invoke-Pester` directly in VS Code terminal.**
Always use `Start-Process` with log polling (see techContext.md).

## Completed

- Extracted 24 functions into source/Public/ (16) and source/Private/ (8)
- Created RC4-ADAssessment module manifest and psm1
- Added Sampler build infrastructure (build.ps1, build.yaml, GitVersion.yml, etc.)
- Created tests/Unit/ with 29 test files (383 passed, 24 skipped, 407 total)
- Created tests/QA/ module quality tests
- Fixed PS 5.1 compatibility: `@($events)` wrapping in Get-EventLogEncryptionAnalysis
- Build succeeds: `Build succeeded. 9 tasks, 0 errors, 0 warnings`
- Memory Bank created with 7 core files
- Created cross-cutting powershell-execution-safety.instructions.md

## Architecture (Post-Migration)

```
source/
  Public/   — 16 exported functions (assessment, display, comparison, orchestration)
  Private/  — 8 internal helpers (formatting, encryption string conversion)
  RC4-ADAssessment.psd1 — Module manifest
  RC4-ADAssessment.psm1 — Module loader (dot-sources Public/ and Private/)
tests/
  QA/       — module quality tests (124 passed, 24 skipped)
  Unit/     — 29 test files (259 passed)
```

## Next Steps

- Update README.md and QUICK_START.md for module-based usage
- Add PSScriptAnalyzer custom rules
- Set up Azure Pipelines CI/CD
- Consider code coverage targets
