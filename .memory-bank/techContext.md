# Tech Context

## Tech Stack

- **Language**: PowerShell 5.1+ (7+ for parallel features)
- **Dependencies**: ActiveDirectory module, GroupPolicy module
- **Testing**: Pester 5.x (204 tests across 4 files)
- **Version Control**: Git, hosted on GitHub (BetaHydri/RC4_AD_Check)
- **License**: MIT

## Development Setup

1. Clone the repository
2. Ensure RSAT tools installed (`ActiveDirectory`, `GroupPolicy` modules)
3. Pester 5.x for testing: `Install-Module Pester -Force -SkipPublisherCheck`
4. Run tests: `Invoke-Pester -Path .\Tests\ -Output Detailed`

## Build System (Target: Sampler)

Migration to Sampler build framework planned:
- ModuleBuilder for module compilation
- InvokeBuild for task automation
- GitVersion for semantic versioning
- PSScriptAnalyzer for code quality
- Pester 5 for testing (already in use)

## Repository Structure (Pre-Migration)

```
RC4_AD_Check/
├── RC4_DES_Assessment.ps1      # Main assessment (4006 lines, 16 functions)
├── Assess-ADForest.ps1         # Forest wrapper (750 lines, 2 functions)
├── Compare-Assessments.ps1     # Comparison tool (354 lines, 3 functions)
├── Tests/
│   ├── RC4_DES_Assessment.Tests.ps1     # 2501 lines
│   ├── Assess-ADForest.Tests.ps1        # 487 lines
│   ├── Compare-Assessments.Tests.ps1    # 455 lines
│   └── Test-EventLogFailureHandling.ps1 # 252 lines
├── archive/                    # Legacy v1.0 files
├── docs/                       # Screenshots
├── CHANGELOG.md
├── QUICK_START.md
├── README.md
└── LICENSE
```

## Constraints

- Must work on Windows PowerShell 5.1 (many AD environments don't have PS 7)
- Cannot require internet access during assessment (air-gapped networks)
- Must mock all AD cmdlets for testing (tests run without AD environment)
- Event log queries require WinRM or RPC connectivity to DCs

## Contributors

- **BetaHydri** (Jan Tiedemann) — 194 commits, primary author
- **Jan Tiedemann** — 89 commits (same person, different git config)
