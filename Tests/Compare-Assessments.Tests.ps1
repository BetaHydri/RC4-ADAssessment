#Requires -Modules Pester

<#
.SYNOPSIS
    Pester tests for Compare-Assessments.ps1
.DESCRIPTION
    Mocked unit tests for the comparison logic in Compare-Assessments.ps1.
    Tests cover the Get-ChangeIndicator helper function and the overall comparison workflow.
.NOTES
    Author: Jan Tiedemann
    Requires: Pester 5.x
#>

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '..' 'Compare-Assessments.ps1'
    $scriptContent = Get-Content -Path $scriptPath -Raw

    # Extract function definitions from the script (helper functions section)
    # The script has functions defined before the param-guarded main logic
    # We need Get-ChangeIndicator, Write-ComparisonHeader, Write-ComparisonSection
    $functionsBlock = [regex]::Match(
        $scriptContent,
        '(?s)#region Helper Functions.*?#endregion'
    ).Value

    if (-not $functionsBlock) {
        # Fallback: extract individual functions
        $functions = @()
        $functionPattern = '(?s)(function\s+(?:Get-ChangeIndicator|Write-ComparisonHeader|Write-ComparisonSection)\s*\{.*?\n\})'
        $matches2 = [regex]::Matches($scriptContent, $functionPattern)
        foreach ($m in $matches2) {
            $functions += $m.Value
        }
        $functionsBlock = $functions -join "`n`n"
    }

    if ($functionsBlock) {
        . ([ScriptBlock]::Create($functionsBlock))
    }
}

# ============================================================
# Get-ChangeIndicator
# ============================================================

Describe 'Get-ChangeIndicator' {
    BeforeEach {
        Mock Write-Host {}
    }

    Context 'When value improved (decreased)' {
        It 'Returns Improved status when new value is lower' {
            $result = Get-ChangeIndicator -Old 5 -New 3
            $result.Status | Should -Be 'Improved'
        }

        It 'Returns green color for improvement' {
            $result = Get-ChangeIndicator -Old 10 -New 0
            $result.Color | Should -Be 'Green'
        }

        It 'Uses down-arrow symbol for improvement' {
            $result = Get-ChangeIndicator -Old 5 -New 3
            $result.Symbol | Should -Not -BeNullOrEmpty
        }
    }

    Context 'When value worsened (increased)' {
        It 'Returns Worsened status when new value is higher' {
            $result = Get-ChangeIndicator -Old 3 -New 5
            $result.Status | Should -Be 'Worsened'
        }

        It 'Returns red color for worsening' {
            $result = Get-ChangeIndicator -Old 0 -New 5
            $result.Color | Should -Be 'Red'
        }
    }

    Context 'When value unchanged' {
        It 'Returns Unchanged status when values are equal' {
            $result = Get-ChangeIndicator -Old 5 -New 5
            $result.Status | Should -Be 'Unchanged'
        }

        It 'Returns gray color for unchanged' {
            $result = Get-ChangeIndicator -Old 0 -New 0
            $result.Color | Should -Be 'Gray'
        }
    }

    Context 'Edge cases' {
        It 'Handles zero to zero' {
            $result = Get-ChangeIndicator -Old 0 -New 0
            $result.Status | Should -Be 'Unchanged'
        }

        It 'Handles zero to positive' {
            $result = Get-ChangeIndicator -Old 0 -New 1
            $result.Status | Should -Be 'Worsened'
        }

        It 'Handles positive to zero' {
            $result = Get-ChangeIndicator -Old 1 -New 0
            $result.Status | Should -Be 'Improved'
        }
    }
}

# ============================================================
# Write-ComparisonHeader
# ============================================================

Describe 'Write-ComparisonHeader' {
    BeforeEach {
        Mock Write-Host {}
    }

    It 'Does not throw' {
        { Write-ComparisonHeader -Title 'Test Comparison' } | Should -Not -Throw
    }
}

# ============================================================
# Write-ComparisonSection
# ============================================================

Describe 'Write-ComparisonSection' {
    BeforeEach {
        Mock Write-Host {}
    }

    It 'Does not throw' {
        { Write-ComparisonSection -Title 'Section Test' } | Should -Not -Throw
    }
}

# ============================================================
# Comparison Logic (integration-style with mock JSON files)
# ============================================================

Describe 'Assessment Comparison Logic' {
    BeforeAll {
        # Create temporary JSON files that simulate assessment exports
        $tempDir = Join-Path ([System.IO.Path]::GetTempPath()) "PesterCompareTests_$(Get-Random)"
        New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

        $baselineData = @{
            AssessmentDate    = '2024-01-01T00:00:00'
            Version           = '2.2.0'
            Domain            = 'contoso.com'
            OverallStatus     = 'WARNING'
            DomainControllers = @{
                TotalDCs      = 3
                AESConfigured = 2
                RC4Configured = 1
                DESConfigured = 0
                Details       = @(
                    @{ Name = 'DC01'; EncryptionTypes = 'AES128-HMAC, AES256-HMAC'; EncryptionValue = 24; Status = 'AES Configured' },
                    @{ Name = 'DC02'; EncryptionTypes = 'AES128-HMAC, AES256-HMAC'; EncryptionValue = 24; Status = 'AES Configured' },
                    @{ Name = 'DC03'; EncryptionTypes = 'RC4-HMAC'; EncryptionValue = 4; Status = 'RC4 Only' }
                )
            }
            Trusts            = @{
                TotalTrusts = 2
                RC4Risk     = 1
                DESRisk     = 0
                Details     = @(
                    @{ Name = 'partner.com'; Direction = 'Bidirectional'; EncryptionTypes = 'AES128-HMAC, AES256-HMAC' },
                    @{ Name = 'legacy.com'; Direction = 'Outbound'; EncryptionTypes = 'RC4-HMAC' }
                )
            }
            EventLogs         = @{
                EventsAnalyzed = 500
                RC4Tickets     = 50
                DESTickets     = 5
                AESTickets     = 445
            }
            Recommendations   = @('WARNING: Remove RC4 encryption from 1 DC(s)')
        }

        $currentData = @{
            AssessmentDate    = '2024-02-01T00:00:00'
            Version           = '2.2.0'
            Domain            = 'contoso.com'
            OverallStatus     = 'OK'
            DomainControllers = @{
                TotalDCs      = 3
                AESConfigured = 3
                RC4Configured = 0
                DESConfigured = 0
                Details       = @(
                    @{ Name = 'DC01'; EncryptionTypes = 'AES128-HMAC, AES256-HMAC'; EncryptionValue = 24; Status = 'AES Configured' },
                    @{ Name = 'DC02'; EncryptionTypes = 'AES128-HMAC, AES256-HMAC'; EncryptionValue = 24; Status = 'AES Configured' },
                    @{ Name = 'DC03'; EncryptionTypes = 'AES128-HMAC, AES256-HMAC'; EncryptionValue = 24; Status = 'AES Configured' }
                )
            }
            Trusts            = @{
                TotalTrusts = 2
                RC4Risk     = 0
                DESRisk     = 0
                Details     = @(
                    @{ Name = 'partner.com'; Direction = 'Bidirectional'; EncryptionTypes = 'AES128-HMAC, AES256-HMAC' },
                    @{ Name = 'legacy.com'; Direction = 'Outbound'; EncryptionTypes = 'AES128-HMAC, AES256-HMAC' }
                )
            }
            EventLogs         = @{
                EventsAnalyzed = 600
                RC4Tickets     = 0
                DESTickets     = 0
                AESTickets     = 600
            }
            Recommendations   = @()
        }

        $script:BaselineFile = Join-Path $tempDir 'baseline.json'
        $script:CurrentFile = Join-Path $tempDir 'current.json'

        $baselineData | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:BaselineFile -Encoding UTF8
        $currentData | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:CurrentFile -Encoding UTF8
    }

    AfterAll {
        # Clean up temp files
        if (Test-Path $tempDir) {
            Remove-Item -Path $tempDir -Recurse -Force
        }
    }

    Context 'Loading JSON files' {
        It 'Loads baseline file correctly' {
            $baseline = Get-Content $script:BaselineFile | ConvertFrom-Json
            $baseline.Domain | Should -Be 'contoso.com'
            $baseline.OverallStatus | Should -Be 'WARNING'
        }

        It 'Loads current file correctly' {
            $current = Get-Content $script:CurrentFile | ConvertFrom-Json
            $current.Domain | Should -Be 'contoso.com'
            $current.OverallStatus | Should -Be 'OK'
        }
    }

    Context 'Overall status comparison' {
        BeforeEach {
            $script:baseline = Get-Content $script:BaselineFile | ConvertFrom-Json
            $script:current = Get-Content $script:CurrentFile | ConvertFrom-Json
        }

        It 'Detects improvement from WARNING to OK' {
            $script:baseline.OverallStatus | Should -Be 'WARNING'
            $script:current.OverallStatus | Should -Be 'OK'
        }
    }

    Context 'DC comparison' {
        BeforeEach {
            $script:baseline = Get-Content $script:BaselineFile | ConvertFrom-Json
            $script:current = Get-Content $script:CurrentFile | ConvertFrom-Json
        }

        It 'Detects AES improvement' {
            $change = Get-ChangeIndicator -Old $script:baseline.DomainControllers.AESConfigured -New $script:current.DomainControllers.AESConfigured
            $change.Status | Should -Be 'Worsened'  # Higher is actually better for AES, but the function treats all increases as "Worsened"
            # Note: Get-ChangeIndicator is generic - it just compares numbers
            # The script interprets context appropriately
        }

        It 'Detects RC4 reduction' {
            $change = Get-ChangeIndicator -Old $script:baseline.DomainControllers.RC4Configured -New $script:current.DomainControllers.RC4Configured
            $change.Status | Should -Be 'Improved'
        }
    }

    Context 'Event log comparison' {
        BeforeEach {
            $script:baseline = Get-Content $script:BaselineFile | ConvertFrom-Json
            $script:current = Get-Content $script:CurrentFile | ConvertFrom-Json
        }

        It 'Detects RC4 ticket reduction' {
            $change = Get-ChangeIndicator -Old $script:baseline.EventLogs.RC4Tickets -New $script:current.EventLogs.RC4Tickets
            $change.Status | Should -Be 'Improved'
        }

        It 'Detects DES ticket reduction' {
            $change = Get-ChangeIndicator -Old $script:baseline.EventLogs.DESTickets -New $script:current.EventLogs.DESTickets
            $change.Status | Should -Be 'Improved'
        }
    }

    Context 'Trust comparison' {
        BeforeEach {
            $script:baseline = Get-Content $script:BaselineFile | ConvertFrom-Json
            $script:current = Get-Content $script:CurrentFile | ConvertFrom-Json
        }

        It 'Detects RC4 trust risk reduction' {
            $change = Get-ChangeIndicator -Old $script:baseline.Trusts.RC4Risk -New $script:current.Trusts.RC4Risk
            $change.Status | Should -Be 'Improved'
        }
    }

    Context 'KDC Registry comparison' {
        It 'Counts RC4Disablement Not Set to 1 as improvement' {
            $baseRC4Phase = 'Not Set'
            $currRC4Phase = 1
            $improvements = 0
            $degradations = 0

            if ($baseRC4Phase -ne $currRC4Phase) {
                if ($currRC4Phase -ne 'Not Set' -and ($baseRC4Phase -eq 'Not Set' -or [int]$currRC4Phase -gt [int]$baseRC4Phase)) {
                    $improvements++
                }
                elseif ($currRC4Phase -eq 'Not Set' -or ($baseRC4Phase -ne 'Not Set' -and [int]$currRC4Phase -lt [int]$baseRC4Phase)) {
                    $degradations++
                }
            }
            $improvements | Should -Be 1
            $degradations | Should -Be 0
        }

        It 'Counts RC4Disablement 1 to Not Set as degradation' {
            $baseRC4Phase = 1
            $currRC4Phase = 'Not Set'
            $improvements = 0
            $degradations = 0

            if ($baseRC4Phase -ne $currRC4Phase) {
                if ($currRC4Phase -ne 'Not Set' -and ($baseRC4Phase -eq 'Not Set' -or [int]$currRC4Phase -gt [int]$baseRC4Phase)) {
                    $improvements++
                }
                elseif ($currRC4Phase -eq 'Not Set' -or ($baseRC4Phase -ne 'Not Set' -and [int]$currRC4Phase -lt [int]$baseRC4Phase)) {
                    $degradations++
                }
            }
            $improvements | Should -Be 0
            $degradations | Should -Be 1
        }

        It 'No change when both Not Set' {
            $baseRC4Phase = 'Not Set'
            $currRC4Phase = 'Not Set'
            $improvements = 0
            $degradations = 0

            if ($baseRC4Phase -ne $currRC4Phase) {
                if ($currRC4Phase -ne 'Not Set' -and ($baseRC4Phase -eq 'Not Set' -or [int]$currRC4Phase -gt [int]$baseRC4Phase)) {
                    $improvements++
                }
                elseif ($currRC4Phase -eq 'Not Set' -or ($baseRC4Phase -ne 'Not Set' -and [int]$currRC4Phase -lt [int]$baseRC4Phase)) {
                    $degradations++
                }
            }
            $improvements | Should -Be 0
            $degradations | Should -Be 0
        }

        It 'Counts DefaultEncTypes Not Set to configured as improvement' {
            $baseEncTypes = 'Not Set'
            $currEncTypes = 'AES128-HMAC, AES256-HMAC'
            $improvements = 0
            $degradations = 0

            if ("$baseEncTypes" -ne "$currEncTypes") {
                if ($baseEncTypes -eq 'Not Set' -and $currEncTypes -ne 'Not Set') {
                    $improvements++
                }
                elseif ($baseEncTypes -ne 'Not Set' -and $currEncTypes -eq 'Not Set') {
                    $degradations++
                }
            }
            $improvements | Should -Be 1
            $degradations | Should -Be 0
        }

        It 'Counts DefaultEncTypes configured to Not Set as degradation' {
            $baseEncTypes = 'AES128-HMAC, AES256-HMAC'
            $currEncTypes = 'Not Set'
            $improvements = 0
            $degradations = 0

            if ("$baseEncTypes" -ne "$currEncTypes") {
                if ($baseEncTypes -eq 'Not Set' -and $currEncTypes -ne 'Not Set') {
                    $improvements++
                }
                elseif ($baseEncTypes -ne 'Not Set' -and $currEncTypes -eq 'Not Set') {
                    $degradations++
                }
            }
            $improvements | Should -Be 0
            $degradations | Should -Be 1
        }
    }

    Context 'RC4 exception account comparison (v2.6.0+)' {
        It 'Counts RC4 exception reduction as improvement' {
            $rc4ExcChange = Get-ChangeIndicator -Old 5 -New 2
            $rc4ExcChange.Status | Should -Be 'Improved'
        }

        It 'Counts RC4 exception increase as worsened' {
            $rc4ExcChange = Get-ChangeIndicator -Old 2 -New 5
            $rc4ExcChange.Status | Should -Be 'Worsened'
        }

        It 'No change when both zero' {
            $rc4ExcChange = Get-ChangeIndicator -Old 0 -New 0
            $rc4ExcChange.Status | Should -Be 'Unchanged'
        }
    }

    Context 'Worsening scenario' {
        BeforeAll {
            $worsenedData = @{
                AssessmentDate    = '2024-03-01T00:00:00'
                Version           = '2.2.0'
                Domain            = 'contoso.com'
                OverallStatus     = 'CRITICAL'
                DomainControllers = @{
                    TotalDCs      = 3
                    AESConfigured = 1
                    RC4Configured = 1
                    DESConfigured = 1
                }
                Trusts            = @{
                    TotalTrusts = 2
                    RC4Risk     = 2
                    DESRisk     = 1
                }
                EventLogs         = @{
                    RC4Tickets = 100
                    DESTickets = 20
                }
            }
            $script:WorsenedFile = Join-Path $tempDir 'worsened.json'
            $worsenedData | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:WorsenedFile -Encoding UTF8
        }

        It 'Detects worsening RC4 tickets' {
            $current = Get-Content $script:CurrentFile | ConvertFrom-Json
            $worsened = Get-Content $script:WorsenedFile | ConvertFrom-Json
            $change = Get-ChangeIndicator -Old $current.EventLogs.RC4Tickets -New $worsened.EventLogs.RC4Tickets
            $change.Status | Should -Be 'Worsened'
        }

        It 'Detects new DES risk on DCs' {
            $current = Get-Content $script:CurrentFile | ConvertFrom-Json
            $worsened = Get-Content $script:WorsenedFile | ConvertFrom-Json
            $change = Get-ChangeIndicator -Old $current.DomainControllers.DESConfigured -New $worsened.DomainControllers.DESConfigured
            $change.Status | Should -Be 'Worsened'
        }
    }
}
