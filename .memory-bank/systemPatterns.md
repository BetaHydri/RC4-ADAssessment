# System Patterns

## Architecture

The project is structured as three standalone PowerShell scripts with embedded functions:

### Scripts

| Script | Role | Functions |
|--------|------|-----------|
| `RC4_DES_Assessment.ps1` | Main assessment tool | 16 functions + 800-line main execution block |
| `Assess-ADForest.ps1` | Forest-wide wrapper | 2 functions (Show-ForestSummary, Invoke-DomainAssessment) |
| `Compare-Assessments.ps1` | Assessment comparison | 3 functions (Write-ComparisonHeader, Write-ComparisonSection, Get-ChangeIndicator) |

### Function Categories

**Private/Helper Functions** (6):
- `Write-Header`, `Write-Section`, `Write-Finding` — Console output formatting
- `Get-EncryptionTypeString` — Encryption value to human-readable string
- `Get-TicketEncryptionType` — Event log encryption type to name mapping
- `ConvertFrom-LastLogonTimestamp` — FileTime Int64 to DateTime conversion

**Public/Assessment Functions** (10):
- `Get-DomainControllerEncryption` — DC encryption + GPO assessment
- `Get-TrustEncryptionAssessment` — Trust encryption evaluation
- `Get-KdcRegistryAssessment` — KDC registry key checks
- `Get-KdcSvcEventAssessment` — KDCSVC event scanning
- `Get-AuditPolicyCheck` — Audit policy verification
- `Get-EventLogEncryptionAnalysis` — 4768/4769 event analysis
- `Get-AccountEncryptionAssessment` — Account encryption status
- `Show-AssessmentSummary` — Results display
- `Show-ManualValidationGuidance` — Guidance display
- `Get-GuidancePlainText` — Plain text guidance generation

## Design Patterns

- **Pipeline pattern**: Each assessment function returns a structured hashtable
- **Progressive disclosure**: QuickScan (config only) vs FullScan (with event logs)
- **Export pattern**: JSON for machine consumption, CSV for spreadsheet analysis
- **Comparison pattern**: Baseline vs current JSON files for progress tracking
- **WinRM/RPC fallback**: Event log queries try Invoke-Command first, fall back to Get-WinEvent -ComputerName
- **PS 5.1 safety**: Always wrap collections in `@()` before using `.Count` (no intrinsic `.Count` on scalars in 5.1)

## Testing Pattern

Pester 5 tests dot-source functions from `source/` directories:
1. `BeforeAll` creates global stubs for AD/GP cmdlets (parameter-compatible)
2. `BeforeEach` mocks specific cmdlets per context
3. Functions tested in isolation with structured hashtable assertions
4. Build runs tests via Sampler `Pester_Tests_Stop_On_Fail` task

## Build Pattern (Sampler)

- `build.ps1 -ResolveDependency` — first-time setup
- `build.ps1 -Tasks build` — compile module to output/builtModule/
- `build.ps1 -Tasks test` — build + run all tests
- GitVersion drives versioning (ContinuousDelivery, next-version: 3.0.0)

## Key Conventions

- Version managed by GitVersion (no manual version strings)
- Assessment results are structured hashtables with consistent property names
- Console output uses `Write-Host` with color coding (Green=OK, Yellow=WARNING, Red=CRITICAL)
- All AD queries use `@ServerParams` splatting for DC targeting
- Functions use `[CmdletBinding()]` with proper parameter declarations
