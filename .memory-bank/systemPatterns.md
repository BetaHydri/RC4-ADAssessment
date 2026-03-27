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
- **Mock-friendly design**: All AD cmdlets are mockable; tests use regex extraction

## Testing Pattern

Tests use Pester 5 with a regex-based function extraction pattern:
1. Read script content as raw string
2. Extract function block using regex
3. Dot-source the extracted functions via `ScriptBlock::Create()`
4. Mock AD/GP cmdlets with parameter-compatible stubs
5. Test functions in isolation

## Key Conventions

- Version tracked in script metadata, README, CHANGELOG, and test files
- Assessment results are structured hashtables with consistent property names
- Console output uses `Write-Host` with color coding (Green=OK, Yellow=WARNING, Red=CRITICAL)
- All AD queries use `@serverParams` splatting for DC targeting
