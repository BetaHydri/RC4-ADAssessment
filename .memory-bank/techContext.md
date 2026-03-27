# Tech Context

## Tech Stack

- **Language**: PowerShell 5.1+ (7+ for parallel features)
- **Build Framework**: Sampler (ModuleBuilder, InvokeBuild, GitVersion)
- **Dependencies**: ActiveDirectory module, GroupPolicy module
- **Testing**: Pester 5.x (407 tests across 29 files)
- **Version Control**: Git, hosted on GitHub (BetaHydri/RC4_AD_Check)
- **License**: MIT

## Development Setup

1. Clone the repository
2. Ensure RSAT tools installed (`ActiveDirectory`, `GroupPolicy` modules)
3. First build: `pwsh -NoProfile -NonInteractive -Command './build.ps1 -ResolveDependency'` (in external terminal)
4. Subsequent builds: use `Start-Process` detached (see below)

## CRITICAL: Running Builds and Tests

**NEVER** run `build.ps1`, `Invoke-Pester`, or any long-running command directly in the
VS Code integrated terminal. Even `pwsh -Command '...'` can hang VS Code.

**ALWAYS use `Start-Process` (fully detached) with log polling:**

```powershell
$logPath = Join-Path $PWD 'output\test.log'
Remove-Item $logPath -ErrorAction SilentlyContinue
Start-Process -FilePath pwsh -ArgumentList @(
    '-NoProfile', '-NonInteractive', '-Command',
    "Set-Location '$PWD'; .\build.ps1 -Tasks test *>&1 | Out-File -FilePath '$logPath' -Encoding utf8"
) -WindowStyle Hidden -PassThru

for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep 3
    if (Test-Path $logPath) {
        $c = Get-Content $logPath -Raw -ErrorAction SilentlyContinue
        if ($c -match 'Build (FAILED|succeeded)') {
            Get-Content $logPath -Tail 30
            break
        }
    }
}
```

## Build System (Sampler — Active)

Sampler build framework fully operational:
- **ModuleBuilder** for module compilation (source/ → output/builtModule/)
- **InvokeBuild** for task automation (`build.ps1 -Tasks test|build|pack`)
- **GitVersion** for semantic versioning (ContinuousDelivery mode, next-version: 3.0.0)
- **PSScriptAnalyzer** for code quality
- **Pester 5** for testing (407 tests, 0 failures)

## Repository Structure (Post-Migration)

```
RC4_AD_Check/
├── source/
│   ├── Public/          # 16 exported functions
│   ├── Private/         # 8 internal helpers
│   ├── RC4ADCheck.psd1  # Module manifest
│   └── RC4ADCheck.psm1  # Module loader
├── tests/
│   ├── Unit/            # 29 test files (259 passed)
│   └── QA/              # Module quality tests (124 passed, 24 skipped)
├── output/              # Build output (gitignored)
│   ├── builtModule/     # Compiled module
│   ├── RequiredModules/ # Build dependencies
│   └── testResults/     # NUnit XML + Pester objects
├── archive/             # Legacy v1.0 files
├── build.ps1            # Sampler bootstrap
├── build.yaml           # Build configuration
├── GitVersion.yml       # Versioning config
├── CHANGELOG.md
├── QUICK_START.md       # (needs update for module usage)
├── README.md            # (needs update for module usage)
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
